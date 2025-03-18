function createLoaderElement() {
    return '<div class="spinner-border me-auto p-2 spinner-border-sm text-secondary" role="status"></div>'
}


function createGreenTick() {
    return '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="text-success m-2 icon icon-tabler icons-tabler-outline icon-tabler-check"><path stroke="none" d="M0 0h24v24H0z" fill="none"/><path d="M5 12l5 5l10 -10" /></svg>';
}

function createRedCross() {
    return '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="text-danger m-2 icon icon-tabler icons-tabler-outline icon-tabler-x"><path stroke="none" d="M0 0h24v24H0z" fill="none"/><path d="M18 6l-12 12" /><path d="M6 6l12 12" /></svg>';
}

function createAlertElement(type, message) {
    const div = document.createElement('div');
    div.className = `alert alert-important alert-${type} m-0 me-auto p-2`;
    div.setAttribute('role', 'alert');

    const alertIconDiv = document.createElement('div');
    alertIconDiv.className = 'alert-icon';

    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('xmlns', 'http://www.w3.org/2000/svg');
    svg.setAttribute('width', '24');
    svg.setAttribute('height', '24');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('fill', 'none');
    svg.setAttribute('stroke', 'currentColor');
    svg.setAttribute('stroke-width', '2');
    svg.setAttribute('stroke-linecap', 'round');
    svg.setAttribute('stroke-linejoin', 'round');
    svg.className = 'icon alert-icon icon-2';

    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    if (type === 'success') {
        path.setAttribute('d', 'M5 12l5 5l10 -10');
    } else if (type === 'error') {
        path.setAttribute('d', 'M3 12a9 9 0 1 0 18 0a9 9 0 0 0 -18 0');
        const path2 = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        path2.setAttribute('d', 'M12 8v4');
        const path3 = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        path3.setAttribute('d', 'M12 16h.01');
        svg.appendChild(path2);
        svg.appendChild(path3);
    } else if (type === 'warning') {
        path.setAttribute('d', 'M10.363 3.591l-8.106 13.534a1.914 1.914 0 0 0 1.636 2.871h16.214a1.914 1.914 0 0 0 1.636 -2.87l-8.106 -13.536a1.914 1.914 0 0 0 -3.274 0z');
    }

    svg.appendChild(path);
    alertIconDiv.appendChild(svg);
    div.appendChild(alertIconDiv);

    const alertContentDiv = document.createElement('div');
    const alertDescription = document.createElement('div');
    alertDescription.className = 'alert-description';
    alertDescription.textContent = message;
    alertContentDiv.appendChild(alertDescription);

    div.appendChild(alertContentDiv);

    return div;
}