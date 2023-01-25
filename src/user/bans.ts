// import winston from 'winston';

// import meta from '../meta';
// import emailer from '../emailer';
// import db from '../database';
// import groups from '../groups';
// import privileges from '../privileges';
import winston = require('winston');

import meta = require('../meta');
import emailer = require('../emailer');
import db = require('../database');
import groups = require('../groups');
import privileges = require('../privileges');

interface UserObject {
    bans : BansObject;
    setUserField: (uid: string, field: string, value: number) => Promise<void>;
    getUserField: (uid: string, field: string,) => Promise<DataObject>;
    getUsersFields: (uid: string[], fields: string[]) => Promise<DataObject[]>;
}

interface BansObject {
    ban;
    unban;
    isBanned;
    canLoginIfBanned;
    unbanIfExpired;
    calcExpiredFromUserData;
    filterBanned;
    getReason;
}

interface DataObject {
    uids: string[];
    uid: string;
}

interface BanDataObject {
    uid;
    timestamp;
    expire : number;
    reason;
}

module.exports = function (User : UserObject) {
    User.bans.ban = async function (uid : string, until : number, reason : string) {
        // "until" (optional) is unix timestamp in milliseconds
        // "reason" (optional) is a string
        until = until || 0;
        reason = reason || '';

        const now = Date.now();

        until = parseInt(String(until), 10);
        if (isNaN(until)) {
            throw new Error('[[error:ban-expiry-missing]]');
        }

        const banKey = `uid:${uid}:ban:${now}`;
        const banData : BanDataObject = {
            uid: uid,
            timestamp: now,
            expire: until > now ? until : 0,
        } as BanDataObject;
        if (reason) {
            banData.reason = reason;
        }

        // Leaving all other system groups to have privileges constrained to the "banned-users" group
        // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
        const systemGroups = groups.systemGroups.filter(group => group !== groups.BANNED_USERS);
        // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
        await groups.leave(systemGroups, uid);
        // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
        await groups.join(groups.BANNED_USERS, uid);
        // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
        await db.sortedSetAdd('users:banned', now, uid);
        // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
        await db.sortedSetAdd(`uid:${uid}:bans:timestamp`, now, banKey);
        // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
        await db.setObject(banKey, banData);
        await User.setUserField(uid, 'banned:expire', banData.expire);
        if (until > now) {
            // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
            await db.sortedSetAdd('users:banned:expire', until, uid);
        } else {
            // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
            await db.sortedSetRemove('users:banned:expire', uid);
        }

        // Email notification of ban
        const username = await User.getUserField(uid, 'username');
        // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
        const siteTitle : string = (meta.config.title || 'NodeBB') as string;

        const data = {
            subject: `[[email:banned.subject, ${siteTitle}]]`,
            username: username,
            until: until ? (new Date(until)).toUTCString().replace(/,/g, '\\,') : false,
            reason: reason,
        };
        /* eslint-disable-next-line @typescript-eslint/no-unsafe-member-access,
            @typescript-eslint/restrict-template-expressions */
        await emailer.send('banned', uid, data).catch(err => winston.error(`[emailer.send] ${err.stack}`));

        return banData;
    };

    User.bans.unban = async function (uids : string[]) {
        uids = Array.isArray(uids) ? uids : [uids];
        const userData : DataObject[] = await User.getUsersFields(uids, ['email:confirmed']);

        // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
        await db.setObject(uids.map(uid => `user:${uid}`), { 'banned:expire': 0 });

        /* eslint-disable no-await-in-loop */
        for (const user of userData) {
            const systemGroupsToJoin : string[] = [
                'registered-users',
                (parseInt(user['email:confirmed'], 10) === 1 ? 'verified-users' : 'unverified-users'),
            ] as string[];
            // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
            await groups.leave(groups.BANNED_USERS, user.uid);
            // An unbanned user would lost its previous "Global Moderator" status
            // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
            await groups.join(systemGroupsToJoin, user.uid);
        }

        // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
        await db.sortedSetRemove(['users:banned', 'users:banned:expire'], uids);
    };

    User.bans.isBanned = async function (uids) {
        const isArray = Array.isArray(uids);
        uids = isArray ? uids : [uids];
        const result = await User.bans.unbanIfExpired(uids);
        return isArray ? result.map(r => r.banned) : result[0].banned;
    };

    User.bans.canLoginIfBanned = async function (uid) {
        let canLogin = true;

        const { banned } = (await User.bans.unbanIfExpired([uid]))[0];
        // Group privilege overshadows individual one
        if (banned) {
            // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
            canLogin = await privileges.global.canGroup('local:login', groups.BANNED_USERS);
        }
        if (banned && !canLogin) {
            // Checking a single privilege of user
            // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
            canLogin = await groups.isMember(uid, 'cid:0:privileges:local:login');
        }

        return canLogin;
    };

    User.bans.unbanIfExpired = async function (uids) {
        // loading user data will unban if it has expired -barisu
        const userData = await User.getUsersFields(uids, ['banned:expire']);
        return User.bans.calcExpiredFromUserData(userData);
    };

    User.bans.calcExpiredFromUserData = async function (userData) {
        const isArray = Array.isArray(userData);
        userData = isArray ? userData : [userData];
        // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
        const banned = await groups.isMembers(userData.map(u => u.uid), groups.BANNED_USERS);
        userData = userData.map((userData, index) => ({
            banned: banned[index],
            'banned:expire': userData && userData['banned:expire'],
            banExpired: userData && userData['banned:expire'] <= Date.now() && userData['banned:expire'] !== 0,
        }));
        return isArray ? userData : userData[0];
    };

    User.bans.filterBanned = async function (uids) {
        const isBanned = await User.bans.isBanned(uids);
        return uids.filter((uid, index) => !isBanned[index]);
    };

    User.bans.getReason = async function (uid) {
        if (parseInt(uid, 10) <= 0) {
            return '';
        }
        // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
        const keys = await db.getSortedSetRevRange(`uid:${uid}:bans:timestamp`, 0, 0);
        if (!keys.length) {
            return '';
        }
        // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
        const banObj = await db.getObject(keys[0]);
        return banObj && banObj.reason ? banObj.reason : '';
    };
};
