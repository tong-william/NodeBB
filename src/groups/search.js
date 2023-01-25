"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const user_1 = __importDefault(require("../user"));
const database_1 = __importDefault(require("../database"));
function default_1(Groups) {
    Groups.search = function (query, options) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!query) {
                return [];
            }
            query = String(query).toLowerCase();
            // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
            let groupNames = yield database_1.default.getSortedSetRange('groups:createtime', 0, -1);
            if (!options.hideEphemeralGroups) {
                // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
                groupNames = Groups.ephemeralGroups.concat(groupNames);
            }
            groupNames = groupNames.filter(name => name.toLowerCase().includes(query) &&
                name !== Groups.BANNED_USERS && // hide banned-users in searches
                !Groups.isPrivilegeGroup(name));
            groupNames = groupNames.slice(0, 100);
            let groupsData;
            if (options.showMembers) {
                groupsData = yield Promise.resolve(Groups.getGroupsAndMembers(groupNames));
            }
            else {
                groupsData = yield Promise.resolve(Groups.getGroupsData(groupNames));
            }
            // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
            groupsData = groupsData.filter(Boolean);
            if (options.filterHidden) {
                // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
                groupsData = groupsData.filter((group) => (!group.hidden));
            }
            // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
            return Groups.sort(options.sort, groupsData);
        });
    };
    Groups.sort = function (strategy, groups) {
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
    Groups.searchMembers = function (data) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!data.query) {
                const users = yield Groups.getOwnersAndMembers(data.groupName, data.uid, 0, 19);
                return { users: users };
            }
            const results = yield user_1.default.search(Object.assign(Object.assign({}, data), { paginate: false, hardCap: -1 }));
            const uids = results.users.map(user => user && user.uid);
            const isOwners = yield Groups.ownership.isOwners(uids, data.groupName);
            results.users.forEach((user, index) => {
                if (user) {
                    user.isOwner = isOwners[index];
                }
            });
            results.users.sort((a, b) => {
                if (a.isOwner && !b.isOwner) {
                    return -1;
                }
                else if (!a.isOwner && b.isOwner) {
                    return 1;
                }
                return 0;
            });
            return results;
        });
    };
}
exports.default = default_1;
;
