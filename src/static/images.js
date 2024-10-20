function getOrganizationLink(orgName) {
    // Define a mapping between organization names and their corresponding logo URLs
    const orgLogos = {
        'ATHENARC': 'https://stelar-project.eu/wp-content/uploads/2022/09/Anthena-logo-web.jpg',
        'VISTA': 'https://stelar-project.eu/wp-content/uploads/2022/09/vista.jpg',
        'AGROKNOW': 'https://info.agroknow.com/hs-fs/hubfs/logo_agro2.png?width=220&height=124&name=logo_agro2.png',
        'ABACO': 'https://stelar-project.eu/wp-content/uploads/2022/09/Logo_AbacoGroup-274x300.jpg',
        'UOA': 'https://stelar-project.eu/wp-content/uploads/2022/09/The-National-and-Kapodistrian-University-of-Athens-UoA-participates-in-STELAR-with-the-Artificial.jpg',
        'TUE': 'https://stelar-project.eu/wp-content/uploads/2022/09/Eindhoven-University-of-Technology-TUE.jpg'
    };

    // Check if the organization exists in the mapping
    if (orgLogos[orgName]) {
        // Return the hyperlink with the organization's logo
        return orgLogos[orgName];
    } else {
        // Return a default message if the organization is not found
        return ``;
    }
}
