function(limit, ancestorsOnly) {
    // This function runs in an isolated world, not the page's JavaScript
    // realm. Only DOM.describeNode supplies attributes and backend identities.
    const target = this;
    if (!target.isConnected) return null;
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
            if (node.nodeType !== 1) continue;
            if (['input', 'form', 'label'].includes(node.localName) || node.hasAttribute('form')) global = true;
            // Relative activation destinations need the document's first base,
            // including pierced roots, rather than the page's computed URL.
            for (const attr of ['href', 'formaction']) {
                const value = node.getAttribute(attr);
                if (value !== null && !/^[a-z][a-z0-9+.-]*:/i.test(value.trim()) && !value.trim().startsWith('//')) global = true;
            }
            if (node.assignedSlot) chain(node.assignedSlot);
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
        // The legacy classifier stores absolute login-field ordinals and every
        // associated form-control identity. An incomplete context is not safe
        // to classify. This bounded fallback is used only for those facts.
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
        visit(target.ownerDocument || target);
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
    return [JSON.stringify({parents: nodes.map(node => indexes.get(parent(node)) ?? null), complete: global, childCounts}), ...nodes];
}
