import { requireSessionScopeRoute } from './session-scope-router.mjs';

function plain(value) { return value !== null && typeof value === 'object' && !Array.isArray(value); }
function exact(value, keys) { return plain(value) && Object.keys(value).sort().join('\0') === [...keys].sort().join('\0'); }
function same(left, right) { return JSON.stringify(left) === JSON.stringify(right); }

export const STRUCTURED_CANDIDATE_PROPOSAL_SINK_SCHEMA = 'amf.structured-candidate-proposal-sink/v1';

export function createStructuredCandidateProposalSink({ submit } = {}) {
  if (typeof submit !== 'function') throw new Error('structured_candidate_sink_invalid');
  return Object.freeze({
    schema: STRUCTURED_CANDIDATE_PROPOSAL_SINK_SCHEMA,
    async propose(value) {
      if (!exact(value, ['scope', 'routingEvidence', 'candidate', 'idempotencyKey'])
        || typeof value.idempotencyKey !== 'string' || !value.idempotencyKey) throw new Error('structured_candidate_sink_input_invalid');
      const route = requireSessionScopeRoute({ outcome: 'routed', scope: value.scope, routingEvidence: value.routingEvidence });
      const candidate = value.candidate;
      if (!plain(candidate) || candidate.schema !== 'amf.conversation-memory-candidate/v1' || candidate.infer !== false
        || !same(candidate.scope, route.scope) || !same(candidate.routingEvidence, route.routingEvidence)) {
        throw new Error('structured_candidate_sink_input_invalid');
      }
      return submit(value);
    }
  });
}

export function requireStructuredCandidateProposalSink(value) {
  if (!plain(value) || value.schema !== STRUCTURED_CANDIDATE_PROPOSAL_SINK_SCHEMA || typeof value.propose !== 'function') {
    throw new Error('structured_candidate_sink_required');
  }
  return value;
}

// The deployed endpoint accepts a legacy string scope.  It is intentionally
// not an adapter for ScopeRef candidates; server integration must add a new
// structured endpoint/sink before capture can be enabled.
export function legacyHttpProposalSinkUnsupported() {
  throw new Error('structured_candidate_legacy_http_unsupported');
}
