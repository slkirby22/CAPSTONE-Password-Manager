/* Deliberate per-item reveal. DOM cleanup reduces exposure; JS strings cannot
 * be reliably zeroized and this does not protect against a malicious client. */
'use strict';

document.addEventListener('DOMContentLoaded', () => {
    const root = document.getElementById('item-reveal');
    if (!root) return;
    const reveal = document.getElementById('reveal-password');
    const hide = document.getElementById('hide-password');
    const output = document.getElementById('revealed-password');
    const status = document.getElementById('reveal-status');
    const replacementIntent = document.getElementById('replace-password');
    const replacement = document.getElementById('replacement-password');
    let generation = 0;
    let active = false;
    let controller = null;
    let timeout = null;

    function clearReveal() {
        generation++;
        active = false;
        if (controller) controller.abort();
        controller = null;
        if (timeout !== null) clearTimeout(timeout);
        timeout = null;
        output.textContent = '';
        output.hidden = true;
        reveal.disabled = false;
        reveal.setAttribute('aria-expanded', 'false');
        hide.hidden = true;
        status.textContent = '';
    }

    function clearPage() {
        clearReveal();
        // Replacement input is independently entered, never populated by reveal.
        if (replacement) {
            replacement.value = '';
            replacement.disabled = true;
            replacementIntent.checked = false;
            const feedback = document.getElementById('strength-replacement-password');
            if (feedback) feedback.textContent = '';
        }
    }

    reveal.addEventListener('click', async () => {
        // Ignore double clicks while loading or already visible.
        if (active || document.visibilityState === 'hidden') return;
        clearReveal();
        const itemId = root.dataset.itemId;
        if (!/^[0-9a-f]{32}$/.test(itemId)) return;
        const requestGeneration = generation;
        const requestController = new AbortController();
        controller = requestController;
        active = true;
        reveal.disabled = true;
        hide.hidden = false;
        status.textContent = 'Loading password…';
        timeout = setTimeout(clearReveal, 30000);
        let payload = null;
        try {
            const response = await fetch(`/passwords/${itemId}/reveal`, {
                method: 'POST',
                credentials: 'same-origin',
                cache: 'no-store',
                redirect: 'error',
                headers: {'X-CSRFToken': root.dataset.csrfToken, 'Accept': 'application/json'},
                signal: requestController.signal
            });
            if (!response.ok) throw new Error('Unavailable');
            payload = await response.json();
            if (!active || requestGeneration !== generation ||
                requestController.signal.aborted || root.dataset.itemId !== itemId ||
                document.visibilityState === 'hidden') return;
            if (!payload || payload.item_id !== itemId || typeof payload.password !== 'string') {
                throw new Error('Unavailable');
            }
            output.textContent = payload.password;
            output.hidden = false;
            reveal.setAttribute('aria-expanded', 'true');
            status.textContent = 'Password revealed. Use Hide password to clear it.';
        } catch (error) {
            if (requestGeneration === generation && active) {
                clearReveal();
                status.textContent = 'Password unavailable. Please select the item again or sign in.';
            }
        } finally {
            // Do not retain parsed response data after rendering or interruption.
            if (payload && typeof payload === 'object') payload.password = '';
            payload = null;
            if (controller === requestController) controller = null;
        }
    });
    hide.addEventListener('click', clearReveal);
    document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'hidden') clearPage();
    });
    window.addEventListener('pagehide', clearPage);
    window.addEventListener('pageshow', clearPage);
    window.addEventListener('beforeunload', clearPage);
    window.addEventListener('popstate', clearPage);
    // Includes selection links, logout, delete and metadata/replacement submits.
    document.addEventListener('click', event => {
        if (event.target.closest('a')) clearPage();
    }, true);
    // Preserve user-entered replacement long enough for native form submission.
    document.addEventListener('submit', clearReveal, true);
    document.addEventListener('change', event => {
        if (event.target.matches('[data-item-selector]')) clearPage();
    }, true);
    if (replacementIntent && replacement) {
        replacementIntent.addEventListener('change', () => {
            replacement.disabled = !replacementIntent.checked;
            if (!replacementIntent.checked) {
                replacement.value = '';
                const feedback = document.getElementById('strength-replacement-password');
                if (feedback) feedback.textContent = '';
            }
        });
    }
    clearPage();
});
