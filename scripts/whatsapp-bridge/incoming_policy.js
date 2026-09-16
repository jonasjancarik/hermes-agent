// Separate transport group authorization from direct-message sender rules.
export function isBridgeIncomingAllowed({isGroup, chatId, senderId, groupPolicy, dmPolicy, allowedGroups, allowedUsers, matches}) {
  if (isGroup) {
    if (groupPolicy === 'open') return true;
    return groupPolicy === 'allowlist' && matches(chatId, allowedGroups);
  }
  return dmPolicy !== 'disabled' && (dmPolicy === 'pairing' || matches(senderId, allowedUsers));
}
