function(limit, ancestorsOnly, snapshotState) {
    // This function runs in an isolated world, not the page's JavaScript
    // realm. Native attribute reads are fresh for this call; CDP supplies the
    // backend identities and the shadow details JavaScript cannot observe.
    const target = this;
    if (!target.isConnected) return null;
    const state = snapshotState || {keys: new WeakMap(), next: 1};
    const key = node => {
        if (!state.keys.has(node)) state.keys.set(node, state.next++);
        return state.keys.get(node);
    };
    const parent = node => node.parentNode || (node.nodeType === 11 ? node.host : null);
    const nodes = [], seen = new Set();
    let global = false;
    const add = node => {
        if (!node || seen.has(node)) return;
        if (nodes.length === limit) throw new Error('context bound');
        seen.add(node);
        nodes.push(node);
    };
    const chain = node => {
        for (; node && !seen.has(node); node = parent(node)) {
            add(node);
            if (node.assignedSlot) chain(node.assignedSlot);
            if (node.nodeType !== 1) continue;
            if (['input', 'form', 'label'].includes(node.localName) || node.hasAttribute('form')) global = true;
            // Relative activation destinations need the document's first base,
            // including pierced roots, rather than the page's computed URL.
            for (const attr of ['href', 'formaction']) {
                const value = node.getAttribute(attr);
                if (value !== null && !/^[a-z][a-z0-9+.-]*:/i.test(value.trim()) && !value.trim().startsWith('//')) global = true;
            }
        }
    };
    chain(target);
    if (ancestorsOnly && target.nodeType !== 1) {
        // A text key's span is not enough markup when its value is a sibling.
        // Read bounded local siblings until the first enclosing element adds
        // alphanumeric text, matching the DOM-full enclosure rule.
        const units = value => (value.match(/[\p{L}\p{N}]/gu) || []).length;
        const own = target.nodeType === 3 ? units(target.nodeValue) : 0;
        for (let ancestor = parent(target); ancestor; ancestor = parent(ancestor)) {
            if (ancestor.nodeType !== 1) continue;
            let visited = 0, size = 0;
            const visit = node => {
                if (++visited > limit) throw new Error('context bound');
                if ([1, 3, 9, 11].includes(node.nodeType)) add(node);
                if (node.nodeType === 3) size += units(node.nodeValue);
                for (let child = node.firstChild; child; child = child.nextSibling) visit(child);
            };
            visit(ancestor);
            if (size > own) break;
        }
    }
    if (global && !ancestorsOnly) {
        const document = target.ownerDocument || target;
        state.completeFailures ||= new WeakSet();
        if (state.completeFailures.has(document)) throw new Error('context bound');
        try {
            // Classification needs each login field's position in the complete
            // page and every associated form-control identity. An incomplete
            // context cannot safely supply those facts.
            // Keep the exact graph, including hidden controls and duplicate IDs.
            // A form's layout wrappers must not exhaust a fixed page-node quota:
            // allow 32 graph nodes per control, with a hard transport/memory cap.
            const hardLimit = 16384;
            let scanned = 0, controls = 0;
            const count = node => {
                if (++scanned > hardLimit) throw new Error('context bound');
                if (['input', 'button', 'select', 'textarea', 'output'].includes(node.localName)) ++controls;
                if (node.nodeType === 1 && node.shadowRoot) count(node.shadowRoot);
                for (let child = node.firstChild; child; child = child.nextSibling) {
                    if (child.nodeType === 3 && !child.nodeValue.trim()) continue;
                    count(child);
                }
            };
            count(document);
            limit = Math.min(hardLimit, limit + controls * 32);
            nodes.length = 0;
            seen.clear();
            let visited = 0;
            const visit = node => {
                if (++visited > limit) throw new Error('context bound');
                if (node.nodeType === 1 && node.shadowRoot) visit(node.shadowRoot);
                for (let child = node.firstChild; child; child = child.nextSibling) {
                    if (child.nodeType === 3 && !child.nodeValue.trim()) continue;
                    visit(child);
                }
                if ([1, 3, 9, 11].includes(node.nodeType)) add(node);
            };
            visit(document);
        } catch (error) {
            // One oversized document must not be rescanned for every captured
            // field in the same synchronous snapshot call.
            state.completeFailures.add(document);
            throw error;
        }
    }
    if (ancestorsOnly) global = false;
    const indexes = new Map(nodes.map((node, index) => [node, index]));
    const childCounts = global ? nodes.map(node => {
        let count = 0;
        for (let child = node.firstChild; child; child = child.nextSibling) {
            if (child.nodeType !== 3 || child.nodeValue.trim()) ++count;
        }
        return count;
    }) : [];
    const facts = nodes.map(node => ({
        nodeType: node.nodeType,
        nodeName: node.nodeName,
        localName: node.localName || '',
        nodeValue: node.nodeValue || '',
        ...(node.nodeType === 1 ? {attributes: Array.from(node.attributes, attr => [attr.name, attr.value]).flat()} : {})
    }));
    const result = [JSON.stringify({parents: nodes.map(node => indexes.get(parent(node)) ?? null), complete: global, bound: limit, childCounts,
        keys: nodes.map(key), slots: nodes.map(node => node.assignedSlot ? key(node.assignedSlot) : null), facts}), ...nodes];
    result.state = state;
    return result;
}
