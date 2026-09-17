//! The deterministic interleave: one flattened node order over every
//! intent's graph, in which a node lands after whatever fills every
//! socket and every give it reaches.

use super::AdmissionError;
use super::fill::Wired;

/// One flattened order over every intent's nodes.
pub struct Interleaved {
    /// The flattened position of each (intent, local node).
    pub flat_of: Vec<Vec<u32>>,
    /// The emission order, as (intent, local node) pairs.
    pub order: Vec<(usize, usize)>,
}

/// Deterministic interleave: repeatedly emit the lowest-indexed intent
/// whose next node has every socket it reaches already filled. Intents
/// keep their author order, so acyclicity is judged at socket
/// granularity; a stall is a cycle.
///
pub fn interleave(intents: &[&Wired<'_>], total: usize) -> Result<Interleaved, AdmissionError> {
    let mut cursor = vec![0usize; intents.len()];
    let mut flat_of: Vec<Vec<u32>> = intents
        .iter()
        .map(|view| vec![0u32; view.graph.nodes.len()])
        .collect();
    let mut order: Vec<(usize, usize)> = Vec::with_capacity(total);
    while order.len() < total {
        let mut progressed = false;
        'candidates: for (index, intent) in intents.iter().enumerate() {
            let next = cursor[index];
            let Some(node) = intent.graph.nodes.get(next) else {
                continue;
            };
            // Every socket and every give this node reaches, whichever
            // way it reaches one: an argument consuming the edge that
            // fills a socket or that a member gives, and evidence
            // presenting the proof that fills a socket. Each is a
            // dependency on the node behind it, and a proof left out of
            // this scan would let a node present a claim proven after
            // it ran.
            //
            // An out-of-range reference carries no dependency; the node
            // check below rejects it. A grant stands before any node
            // runs, so the socket it fills waits on nothing.
            let waits_on = node
                .sockets()
                .filter_map(|socket| intent.fill(socket)?.waits_on())
                .chain(node.gives().filter_map(|give| {
                    let produced = intent.resolution.give(give)?;
                    Some((produced.intent, produced.edge.producer))
                }));
            for (source, producer) in waits_on {
                let source = usize::try_from(source).unwrap_or(usize::MAX);
                let producer = usize::try_from(producer).unwrap_or(usize::MAX);
                if cursor
                    .get(source)
                    .is_none_or(|&emitted| producer >= emitted)
                {
                    continue 'candidates;
                }
            }
            flat_of[index][next] =
                u32::try_from(order.len()).map_err(|_| AdmissionError::TooManyNodes)?;
            order.push((index, next));
            cursor[index] += 1;
            progressed = true;
            break;
        }
        if !progressed {
            return Err(AdmissionError::CyclicSockets);
        }
    }

    Ok(Interleaved { flat_of, order })
}
