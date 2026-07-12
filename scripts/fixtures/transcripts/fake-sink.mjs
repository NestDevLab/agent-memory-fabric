export default function createSink() {
  return {
    async deliver(item, { idempotencyKey }) {
      if (item?.event?.eventId !== idempotencyKey) throw new Error('fixture_sink_id_mismatch');
      return { acknowledged: true, eventId: idempotencyKey, duplicate: false };
    }
  };
}
