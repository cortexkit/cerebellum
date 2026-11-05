function(limit, ...targets) {
    // The collector is substituted by Rust from the same source used for action
    // revalidation. All targets and their facts are observed in one JS turn.
    const collect = __COLLECTOR__;
    const state = {keys: new WeakMap(), next: 1};
    const nodes = [], facts = [], childCounts = [], indexes = new Map(), contexts = [], assignments = [];
    let complete = null, completeIndex = null;
    for (const target of targets) {
        try {
            if (complete && complete.slice(1).includes(target)) {
                assignments.push(completeIndex);
                continue;
            }
            const result = collect.call(target, limit, false, state);
            if (!result) throw new Error('disconnected');
            const metadata = JSON.parse(result[0]);
            if (metadata.complete) { complete = result; completeIndex = contexts.length; }
            let invalid = false;
            const members = result.slice(1).map((node, index) => {
                if (!indexes.has(node)) {
                    if (nodes.length === 65535) throw new Error('snapshot context bound');
                    indexes.set(node, nodes.length); nodes.push(node); facts.push(metadata.facts[index]);
                }
                const member = indexes.get(node);
                if (JSON.stringify(facts[member]) !== JSON.stringify(metadata.facts[index])) invalid = true;
                if (metadata.complete) childCounts[member] = metadata.childCounts[index];
                return member;
            });
            assignments.push(contexts.length);
            contexts.push({complete: metadata.complete, bound: metadata.bound, members, invalid});
        } catch (_) { assignments.push(null); }
    }
    const parents = nodes.map(node => indexes.get(node.parentNode || (node.nodeType === 11 ? node.host : null)) ?? null);
    const slots = nodes.map(node => indexes.get(node.assignedSlot) ?? null);
    return [JSON.stringify({contexts, assignments, facts, childCounts, parents, slots}), ...nodes];
}
