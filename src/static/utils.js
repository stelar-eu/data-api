
function formatIsoDate(isoDate, includeSeconds = true) {
    const dateObj = new Date(isoDate);
    const dd = String(dateObj.getDate()).padStart(2, '0');
    const mm = String(dateObj.getMonth() + 1).padStart(2, '0');
    const yyyy = dateObj.getFullYear();
    const hh = String(dateObj.getHours()).padStart(2, '0');
    const min = String(dateObj.getMinutes()).padStart(2, '0');
    if (includeSeconds) {
        const ss = String(dateObj.getSeconds()).padStart(2, '0');
        return `${dd}-${mm}-${yyyy} ${hh}:${min}:${ss}`;
    } else {
        return `${dd}-${mm}-${yyyy} ${hh}:${min}`;
    }
}
function copyToClipboard(elementId) {
    const inputElement = document.getElementById(elementId);
    if (!inputElement) return;

    inputElement.select();
    inputElement.setSelectionRange(0, 99999); // For mobile devices

    navigator.clipboard.writeText(inputElement.value).catch(err => {
        console.error('Failed to copy text: ', err);
    });
}


function createLoaderElement(zeroMargin = false, zeroPadding = false) {
    return '<div class="spinner-border ' + (zeroMargin ? 'm-0' : 'm-2') + ' me-auto ' + (zeroPadding ? 'p-0' : 'p-2') + ' spinner-border-sm text-secondary stelar-loader" role="status"></div>'
}

function clearGithubLink(githubLink) {
    if (!githubLink) return '';

    const repoPath = githubLink.replace(/^(https?:\/\/)?(www\.)?github\.com\//, '');
    return repoPath
}


function getProgrammingLanguageBadge(language) {
    if (!language) return '';

    const languageLower = language.toLowerCase();

    const languageBadges = {
        python: `<span class="badge bg-blue text-blue-fg">
           <svg  xmlns="http://www.w3.org/2000/svg"  width="24"  height="24"  viewBox="0 0 24 24"  fill="none"  stroke="currentColor"  stroke-width="2"  stroke-linecap="round"  stroke-linejoin="round"  class="text-white icon icon-tabler icons-tabler-outline icon-tabler-brand-python"><path stroke="none" d="M0 0h24v24H0z" fill="none"/><path d="M12 9h-7a2 2 0 0 0 -2 2v4a2 2 0 0 0 2 2h3" /><path d="M12 15h7a2 2 0 0 0 2 -2v-4a2 2 0 0 0 -2 -2h-3" /><path d="M8 9v-4a2 2 0 0 1 2 -2h4a2 2 0 0 1 2 2v5a2 2 0 0 1 -2 2h-4a2 2 0 0 0 -2 2v5a2 2 0 0 0 2 2h4a2 2 0 0 0 2 -2v-4" /><path d="M11 6l0 .01" /><path d="M13 18l0 .01" /></svg>Python</span > `,
        javascript: `<span class="badge bg-yellow text-yellow-fg">
            <svg  xmlns="http://www.w3.org/2000/svg"  width="24"  height="24"  viewBox="0 0 24 24"  fill="none"  stroke="currentColor"  stroke-width="2"  stroke-linecap="round"  stroke-linejoin="round"  class="text-white icon icon-tabler icons-tabler-outline icon-tabler-brand-javascript"><path stroke="none" d="M0 0h24v24H0z" fill="none"/><path d="M20 4l-2 14.5l-6 2l-6 -2l-2 -14.5z" /><path d="M7.5 8h3v8l-2 -1" /><path d="M16.5 8h-2.5a.5 .5 0 0 0 -.5 .5v3a.5 .5 0 0 0 .5 .5h1.423a.5 .5 0 0 1 .495 .57l-.418 2.93l-2 .5" /></svg>
                            Javascript
                          </span> `,
        java: `<span class="badge bg-red text-red-fg">
            <svg  xmlns="http://www.w3.org/2000/svg"  width="24"  height="24"  viewBox="0 0 24 24"  fill="none"  stroke="currentColor"  stroke-width="2"  stroke-linecap="round"  stroke-linejoin="round"  class="text-white icon icon-tabler icons-tabler-outline icon-tabler-coffee"><path stroke="none" d="M0 0h24v24H0z" fill="none"/><path d="M3 14c.83 .642 2.077 1.017 3.5 1c1.423 .017 2.67 -.358 3.5 -1c.83 -.642 2.077 -1.017 3.5 -1c1.423 -.017 2.67 .358 3.5 1" /><path d="M8 3a2.4 2.4 0 0 0 -1 2a2.4 2.4 0 0 0 1 2" /><path d="M12 3a2.4 2.4 0 0 0 -1 2a2.4 2.4 0 0 0 1 2" /><path d="M3 10h14v5a6 6 0 0 1 -6 6h-2a6 6 0 0 1 -6 -6v-5z" /><path d="M16.746 16.726a3 3 0 1 0 .252 -5.555" /></svg>
                            Java
                         </span > `,
        ruby: `<span class="badge bg-pink text-pink-fg">
            <svg  xmlns="http://www.w3.org/2000/svg"  width="24"  height="24"  viewBox="0 0 24 24"  fill="none"  stroke="currentColor"  stroke-width="2"  stroke-linecap="round"  stroke-linejoin="round"  class="text-white icon icon-tabler icons-tabler-outline icon-tabler-diamond"><path stroke="none" d="M0 0h24v24H0z" fill="none"/><path d="M6 5h12l3 5l-8.5 9.5a.7 .7 0 0 1 -1 0l-8.5 -9.5l3 -5" /><path d="M10 12l-2 -2.2l.6 -1" /></svg>
                            Ruby
                </span > `,
        go: `< span class="badge bg-azure text-azure-fg" >
        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="text-white icon icon-tabler icons-tabler-outline icon-tabler-brand-golang"><path stroke="none" d="M0 0h24v24H0z" fill="none" /><path d="M15.695 14.305c1.061 1.06 2.953 .888 4.226 -.384c1.272 -1.273 1.444 -3.165 .384 -4.226c-1.061 -1.06 -2.953 -.888 -4.226 .384c-1.272 1.273 -1.444 3.165 -.384 4.226z" /><path d="M12.68 9.233c-1.084 -.497 -2.545 -.191 -3.591 .846c-1.284 1.273 -1.457 3.165 -.388 4.226c1.07 1.06 2.978 .888 4.261 -.384a3.669 3.669 0 0 0 1.038 -1.921h-2.427" /><path d="M5.5 15h-1.5" /><path d="M6 9h-2" /><path d="M5 12h-3" /></svg>
    Go
                          </span > `,
    };

    return languageBadges[languageLower] || `<span class="badge bg-secondary text-secondary-fg">${language}</span>`;
}


function createGreenTick(zeroMargin = false) {
    return '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="text-success stelar-symbol ' + (zeroMargin ? 'm-0' : 'm-2') + ' icon icon-tabler icons-tabler-outline icon-tabler-check"><path stroke="none" d="M0 0h24v24H0z" fill="none"/><path d="M5 12l5 5l10 -10" /></svg>';
}

function createRedCross() {
    return '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="text-danger stelar-symbol ' + (zeroMargin ? 'm-0' : 'm-2') + ' icon icon-tabler icons-tabler-outline icon-tabler-x"><path stroke="none" d="M0 0h24v24H0z" fill="none"/><path d="M18 6l-12 12" /><path d="M6 6l12 12" /></svg>';
}

function createEmptyStateIcon() {
    return '<svg  xmlns="http://www.w3.org/2000/svg"  width="48"  height="48"  viewBox="0 0 24 24"  fill="none"  stroke="currentColor"  stroke-width="2"  stroke-linecap="round"  stroke-linejoin="round"  class="h-25 w-25 p-6 icon icon-tabler icons-tabler-outline icon-tabler-shovel-pitchforks"><path stroke="none" d="M0 0h24v24H0z" fill="none"/><path d="M5 3h4" /><path d="M7 3v12" /><path d="M4 15h6v3a3 3 0 0 1 -6 0v-3z" /><path d="M14 21v-3a3 3 0 0 1 6 0v3" /><path d="M17 21v-18" /></svg>'
}

function createAlertElement(type, message) {
    const div = document.createElement('div');
    div.className = `alert alert - important alert - ${type} m - 0 me - auto p - 2`;
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
    } else if (type === 'danger') {
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