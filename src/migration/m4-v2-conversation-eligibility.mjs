export function isPotentialM4ConversationProjection(projection) {
  if (projection.authoritativeDeletion) {
    return projection.contentType === 'none' && projection.hasContent === false;
  }
  if (!['user', 'assistant'].includes(projection.role)
    || !['inbound', 'outbound'].includes(projection.direction)
    || !['dm', 'group', 'channel', 'thread', 'session'].includes(projection.conversationKind)
    || (projection.role === 'user' && projection.direction !== 'inbound')
    || (projection.role === 'assistant' && projection.direction !== 'outbound')) {
    return false;
  }
  return projection.contentType === 'text' && projection.hasContent === true;
}
