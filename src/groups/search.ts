import user from '../user';
import db from '../database';

interface BigGroups {
    search ;
    sort ;
    BANNED_USERS : string;
    ephemeralGroups ;
    isPrivilegeGroup : (string) => boolean;
    getGroupsAndMembers : (string) => (string[]);
    getGroupsData : (string) => (string[]);
    searchMembers ;
    getOwnersAndMembers ;
    ownership ;
}

interface GroupOptions {
    hideEphemeralGroups ;
    showMembers ;
    filterHidden ;
    sort ;
}

interface GroupGroups {
    sort ;
}

interface GroupData {
    query : string;
    groupName : string;
    uid : number;
}

interface ginter {
    hidden : boolean;
}

export default function (Groups : BigGroups) {
    Groups.search = async function (query : string, options : GroupOptions) : Promise<string[]> {
        if (!query) {
            return [];
        }
        query = String(query).toLowerCase();
        // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
        let groupNames : string[] = await db.getSortedSetRange('groups:createtime', 0, -1) as string[];
        if (!options.hideEphemeralGroups) {
            // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
            groupNames = Groups.ephemeralGroups.concat(groupNames) as string[];
        }
        groupNames = groupNames.filter(name => name.toLowerCase().includes(query) &&
            name !== Groups.BANNED_USERS && // hide banned-users in searches
            !Groups.isPrivilegeGroup(name));
        groupNames = groupNames.slice(0, 100);

        let groupsData;
        if (options.showMembers) {
            groupsData = await Promise.resolve(Groups.getGroupsAndMembers(groupNames));
        } else {
            groupsData = await Promise.resolve(Groups.getGroupsData(groupNames));
        }
        // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
        groupsData = groupsData.filter(Boolean) as string[];
        if (options.filterHidden) {
            // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
            groupsData = groupsData.filter((group : ginter) => (!group.hidden)) as string[];
        }
        // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
        return Groups.sort(options.sort, groupsData as string[]) as Promise<string[]>;
    };

    Groups.sort = function (strategy : string, groups : GroupGroups) {
        switch (strategy) {
        case 'count':
            (groups.sort((a, b) => a.slug > b.slug))
                .sort((a, b) => b.memberCount - a.memberCount);
            break;

        case 'date':
            groups.sort((a, b) => b.createtime - a.createtime);
            break;

        case 'alpha': // intentional fall-through
        default:
            groups.sort((a, b) => (a.slug > b.slug ? 1 : -1));
        }

        return groups;
    };

    Groups.searchMembers = async function (data : GroupData) {
        if (!data.query) {
            const users = await Groups.getOwnersAndMembers(data.groupName, data.uid, 0, 19);
            return { users: users };
        }

        const results = await user.search({
            ...data,
            paginate: false,
            hardCap: -1,
        });

        const uids = results.users.map(user => user && user.uid);
        const isOwners = await Groups.ownership.isOwners(uids, data.groupName);

        results.users.forEach((user, index) => {
            if (user) {
                user.isOwner = isOwners[index];
            }
        });

        results.users.sort((a, b) => {
            if (a.isOwner && !b.isOwner) {
                return -1;
            } else if (!a.isOwner && b.isOwner) {
                return 1;
            }
            return 0;
        });
        return results;
    };
};