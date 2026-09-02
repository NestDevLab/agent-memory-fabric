import { requireSessionScopeRoute, routeSessionScope } from './session-scope-router.mjs';
import { createStructuredCandidateProposalSink, requireStructuredCandidateProposalSink } from './structured-candidate-proposal-sink.mjs';

function plain(value) { return value !== null && typeof value === 'object' && !Array.isArray(value); }
function same(left, right) { return JSON.stringify(left) === JSON.stringify(right); }

// A reader returns only conversation metadata.  The actor is deliberately a
// trusted producer identity supplied by the caller, never inferred from a
// conversation, tag, or legacy scope string.
export function routeReaderSessionScope({ session, manifest, verifier, actor }) {
  if (!plain(session) || typeof session.conversationKind !== 'string' || !plain(session.contextTags)) {
    throw new Error('session_scope_reader_input_invalid');
  }
  return requireSessionScopeRoute(routeSessionScope({ manifest, verifier, actor,
    conversationKind: session.conversationKind, contextTags: session.contextTags }));
}

export function createSessionScopeRouteComposer({ manifest, verifier, actor, candidateSink }) {
  const sink = requireStructuredCandidateProposalSink(candidateSink);
  const routeSession = session => routeReaderSessionScope({ session, manifest, verifier, actor });
  return Object.freeze({
    schema: 'amf.session-scope-route-composer/v1',
    routeSession,
    async proposeCandidate({ session, candidate, idempotencyKey }) {
      const route = routeSession(session);
      if (!plain(candidate) || candidate.schema !== 'amf.conversation-memory-candidate/v1' || candidate.infer !== false
        || !same(candidate.scope, route.scope) || !same(candidate.routingEvidence, route.routingEvidence)) {
        throw new Error('session_scope_candidate_route_mismatch');
      }
      return sink.propose({ scope: candidate.scope, routingEvidence: candidate.routingEvidence, candidate, idempotencyKey });
    }
  });
}

export { createStructuredCandidateProposalSink };
