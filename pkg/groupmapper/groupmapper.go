package groupmapper

import (
	"context"
	"fmt"
	"slices"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	kuser "k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/klog/v2"

	userv1 "github.com/openshift/api/user/v1"
	userclient "github.com/openshift/client-go/user/clientset/versioned/typed/user/v1"
	userinformer "github.com/openshift/client-go/user/informers/externalversions/user/v1"
	userlisterv1 "github.com/openshift/client-go/user/listers/user/v1"
	usercache "github.com/openshift/library-go/pkg/oauth/usercache"

	authapi "github.com/openshift/oauth-server/pkg/api"
)

const (
	groupGeneratedKey = "oauth.openshift.io/generated"
	groupSyncedKeyFmt = "oauth.openshift.io/idp.%s"
)

var _ authapi.UserIdentityMapper = &UserGroupsMapper{}

var _ kuser.Info = &UserInfoGroupsWrapper{}

// UserInfoGroupsWrapper wraps a UserInfo object in order to add extra groups
// retrieved from the identity providers
type UserInfoGroupsWrapper struct {
	userInfo         kuser.Info
	additionalGroups sets.String
}

func (w *UserInfoGroupsWrapper) GetName() string {
	return w.userInfo.GetName()
}

func (w *UserInfoGroupsWrapper) GetUID() string {
	return w.userInfo.GetUID()
}

func (w *UserInfoGroupsWrapper) GetExtra() map[string][]string {
	return w.userInfo.GetExtra()
}

func (w *UserInfoGroupsWrapper) GetGroups() []string {
	groups := w.additionalGroups.Union(sets.NewString(w.userInfo.GetGroups()...))
	return groups.List()
}

// UserGroupsMapper wraps a UserIdentityMapper with a struct that's capable to
// create the groups for a given user based on the provided UserIdentityInfo
type UserGroupsMapper struct {
	delegatedUserMapper authapi.UserIdentityMapper
	groupsClient        userclient.GroupInterface
	groupsLister        userlisterv1.GroupLister
	groupsCache         *usercache.GroupCache
	groupsSynced        func() bool
}

func NewUserGroupsMapper(delegate authapi.UserIdentityMapper, groupInformer userinformer.GroupInformer, groupsClient userclient.GroupInterface, groupsLister userlisterv1.GroupLister) *UserGroupsMapper {
	return &UserGroupsMapper{
		delegatedUserMapper: delegate,
		groupsClient:        groupsClient,
		groupsLister:        groupsLister,
		groupsCache:         usercache.NewGroupCache(groupInformer),
		groupsSynced:        groupInformer.Informer().HasSynced,
	}
}

func (m *UserGroupsMapper) UserFor(identityInfo authapi.UserIdentityInfo) (kuser.Info, error) {
	userInfo, err := m.delegatedUserMapper.UserFor(identityInfo)
	if err != nil {
		return userInfo, err
	}

	identityGroups := sets.NewString(identityInfo.GetProviderGroups()...)
	if err := m.processGroups(identityInfo.GetProviderName(), identityInfo.GetProviderPreferredUserName(), identityGroups); err != nil {
		return nil, err
	}

	return &UserInfoGroupsWrapper{
		userInfo:         userInfo,
		additionalGroups: identityGroups,
	}, nil
}

func (m *UserGroupsMapper) processGroups(idpName, username string, groups sets.String) error {
	dbg(username, "processGroups for idp '%s' and user '%s'", idpName, username)
	err := wait.PollImmediate(1*time.Second, 5*time.Second, func() (bool, error) {
		return m.groupsSynced(), nil
	})
	if err != nil {
		return err
	}

	cachedGroups, err := m.groupsCache.GroupsFor(username)
	if err != nil {
		return err
	}

	removeGroups, addGroups := groupsDiff(cachedGroups, groups)

	// *** DEBUG *** //
	groupsFromClient, groupsFromClientSlice, err := m.userGroupsFromClient(idpName, username)
	if err != nil {
		return err
	}

	cachedGroupsSet := sets.NewString()
	for _, g := range cachedGroups {
		cachedGroupsSet.Insert(g.Name)
	}

	removeGroupsAPI, addGroupsAPI := groupsDiff(groupsFromClientSlice, groups)
	cacheSameAsClient := cachedGroupsSet.Equal(groupsFromClient)
	dbg(username, "provider: %s; user: %s; groupsSynced? %v; remove: %v; add: %v; providerGroups: [%v]; cacheGroups: [%v]; clientGroups: [%v]; cache==client? %v; removeGroups: [%v]; addGroups: [%v]; removeGroupsAPI: [%v]; addGroupsAPI: [%v]",
		idpName,
		username,
		m.groupsSynced(),
		len(removeGroups),
		len(addGroups),
		groups.List(),
		cachedGroupsSet.List(),
		groupsFromClient.List(),
		cacheSameAsClient,
		removeGroups,
		addGroups,
		removeGroupsAPI,
		addGroupsAPI,
	)
	if !cacheSameAsClient {
		for _, providerGroup := range groups.List() {
			pgu, _ := m.groupsLister.Get(providerGroup)
			dbg(username, "LISTER says for provider group %s: users=%v", providerGroup, pgu.Users)
		}
	}
	// *** DEBUG *** //
	// TODO: cache not in sync with lister; investigate

	for _, g := range removeGroups {
		if err := m.removeUserFromGroup(idpName, username, g); err != nil {
			dbg(username, "removing user '%s' from group '%s' failed: %v", username, g, err)
			return err
		}
		cacheGroups, err := m.groupsCache.GroupsFor(username)
		if err != nil {
			dbg(username, "error querying cache after remove: %v", err)
			return err
		}
		cacheGroupsSlice := []string{}
		for _, group := range cacheGroups {
			cacheGroupsSlice = append(cacheGroupsSlice, group.Name)
		}
		if slices.Contains(cacheGroupsSlice, g) {
			dbg(username, "removing user '%s' from group '%s' succeeded but cache groups NOT updated yet! cacheGroups=%v", username, g, cacheGroupsSlice)
		} else {
			dbg(username, "removing user '%s' from group '%s' succeeded; cacheGroups=%v", username, g, cacheGroupsSlice)
		}
	}

	for _, g := range addGroups {
		if err := m.addUserToGroup(idpName, username, g); err != nil {
			dbg(username, "adding user '%s' to group '%s' failed: %v", username, g, err)
			return err
		}
		cacheGroups, err := m.groupsCache.GroupsFor(username)
		if err != nil {
			dbg(username, "error querying cache after add: %v", err)
			return err
		}
		cacheGroupsSlice := []string{}
		for _, group := range cacheGroups {
			cacheGroupsSlice = append(cacheGroupsSlice, group.Name)
		}
		if !slices.Contains(cacheGroupsSlice, g) {
			dbg(username, "adding user '%s' from group '%s' succeeded but cache groups NOT updated yet! cacheGroups=%v", username, g, cacheGroupsSlice)
		} else {
			dbg(username, "adding user '%s' from group '%s' succeeded; cacheGroups=%v", username, g, cacheGroupsSlice)
		}
	}

	return nil
}

func (m *UserGroupsMapper) userGroupsFromClient(idpName, username string) (sets.String, []*userv1.Group, error) {
	clientGroupsList, err := m.groupsClient.List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return nil, nil, err
	}

	clientGroups := sets.NewString()
	clientGroupSlice := []*userv1.Group{}
	for _, group := range clientGroupsList.Items {
		if group.Annotations[fmt.Sprintf(groupSyncedKeyFmt, idpName)] == "synced" && slices.Contains(group.Users, username) {
			clientGroups.Insert(group.Name)
			clientGroupSlice = append(clientGroupSlice, &group)
		}
	}

	return clientGroups, clientGroupSlice, nil
}

func (m *UserGroupsMapper) removeUserFromGroup(idpName, username, group string) error {
	updatedGroup, err := m.groupsLister.Get(group)
	if err != nil {
		if errors.IsNotFound(err) {
			dbg(username, "error for group %s: %v", group, err)
			return nil
		}
		return err
	}

	if len(updatedGroup.Users) == 0 {
		dbg(username, "updated group userlist empty")
		return nil
	}

	if len(updatedGroup.Users) == 1 && updatedGroup.Users[0] == username && updatedGroup.Annotations[groupGeneratedKey] == "true" {
		dbg(username, "DELETE group '%s'", group)
		return m.groupsClient.Delete(context.TODO(), group, metav1.DeleteOptions{})
	}

	// don't perform any actions on the group if it hasn't been synced for this IdP
	if updatedGroup.Annotations[fmt.Sprintf(groupSyncedKeyFmt, idpName)] != "synced" {
		dbg(username, "idp %s not synced: %v", updatedGroup.Annotations)
		return nil
	}

	// find the user and remove it from the slice
	userIdx := -1
	for i, groupUser := range updatedGroup.Users {
		if groupUser == username {
			userIdx = i
			break
		}
	}

	var newUsers []string
	switch userIdx {
	case -1:
		dbg(username, "user not found in lister group: %v", updatedGroup.Users)
		return nil
	case 0:
		newUsers = updatedGroup.Users[1:]
	default:
		newUsers = append(updatedGroup.Users[0:userIdx], updatedGroup.Users[userIdx+1:]...)
	}

	updatedGroupCopy := updatedGroup.DeepCopy()
	updatedGroupCopy.Users = newUsers

	dbg(username, "UPDATE group '%s' with users after removing user '%s': %v", updatedGroupCopy.Name, username, updatedGroupCopy.Users)
	_, err = m.groupsClient.Update(context.TODO(), updatedGroupCopy, metav1.UpdateOptions{})
	return err
}

func (m *UserGroupsMapper) addUserToGroup(idpName, username, group string) error {
	updatedGroup, err := m.groupsLister.Get(group)
	if errors.IsNotFound(err) {
		dbg(username, "CREATE group '%s' with user '%s'", group, username)
		_, err = m.groupsClient.Create(context.TODO(),
			&userv1.Group{
				ObjectMeta: metav1.ObjectMeta{
					Name: group,
					Annotations: map[string]string{
						fmt.Sprintf(groupSyncedKeyFmt, idpName): "synced",
						groupGeneratedKey:                       "true",
					},
				},
				Users: []string{username},
			},
			metav1.CreateOptions{},
		)
		return err
	}
	if err != nil {
		return err
	}

	if updatedGroup.Annotations == nil {
		updatedGroup.Annotations = map[string]string{}
	}

	var onlyAddAnnotation bool
	for _, u := range updatedGroup.Users {
		if u == username {
			if updatedGroup.Annotations[fmt.Sprintf(groupSyncedKeyFmt, idpName)] != "synced" {
				onlyAddAnnotation = true
				break
			}
			dbg(username, "annotation already added")
			return nil
		}
	}

	updatedGroupCopy := updatedGroup.DeepCopy()
	if !onlyAddAnnotation {
		updatedGroupCopy.Users = append(updatedGroup.Users, username)
	}
	updatedGroupCopy.Annotations[fmt.Sprintf(groupSyncedKeyFmt, idpName)] = "synced"

	dbg(username, "UPDATE group '%s' with users: %v", updatedGroupCopy.Name, updatedGroupCopy.Users)
	_, err = m.groupsClient.Update(context.TODO(), updatedGroupCopy, metav1.UpdateOptions{})
	return err
}

func groupsDiff(existing []*userv1.Group, required sets.String) (toRemove, toAdd []string) {
	existingNames := sets.NewString()
	for _, g := range existing {
		existingNames.Insert(g.Name)
	}

	return existingNames.Difference(required).UnsortedList(), required.Difference(existingNames).UnsortedList()
}

func dbg(username, format string, args ...any) {
	klog.Infof(fmt.Sprintf("[OCPBUGS-63228][u=%s] %s", username, format), args...)
}
