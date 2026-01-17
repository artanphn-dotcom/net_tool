/*
 * © 2024 A.V. All rights reserved.
 * Disclaimer: Tools are provided for informational purposes only.
 */

document.addEventListener('DOMContentLoaded', () => {
    // --- General Tool Switching Logic ---
    const sidebarLinks = document.querySelectorAll('#sidebar .nav-link');
    const toolContainers = document.querySelectorAll('.tool-container');
    const toolTitle = document.getElementById('tool-title');

    const toolMeta = {
        'dns-lookup': { title: 'DNS Lookup', container: document.getElementById('dns-lookup-container') },
        'ip-calculator': { title: 'IP/Subnet Calculator', container: document.getElementById('ip-calculator-container') },
        'security-headers': { title: 'Security Headers Analyzer', container: document.getElementById('security-headers-container') },
        'ip-asn-lookup': { title: 'IP & ASN Lookup', container: document.getElementById('ip-asn-lookup-container') },
        'https-latency': { title: 'HTTPS Latency', container: document.getElementById('https-latency-container') },
        'traceroute-visualizer': { title: 'Traceroute Visualizer', container: document.getElementById('traceroute-visualizer-container') }
    };

    sidebarLinks.forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const tool = link.getAttribute('data-tool');
            sidebarLinks.forEach(l => l.classList.remove('active'));
            link.classList.add('active');
            toolTitle.textContent = toolMeta[tool].title;
            toolContainers.forEach(container => {
                container.style.display = 'none';
            });
            toolMeta[tool].container.style.display = 'block';
        });
    });

    // --- DNS Lookup Tool Logic ---
    const dnsLookupForm = document.getElementById('dns-lookup-form');
    const dnsResultsContainer = document.getElementById('results-container');
    if (dnsLookupForm) {
        dnsLookupForm.addEventListener('submit', async (event) => {
            event.preventDefault();
            const domain = document.getElementById('domain-name').value;
            const type = document.getElementById('dns-type').value;
            showLoading(dnsResultsContainer);
            try {
                const response = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=${type}`, { headers: { 'accept': 'application/dns-json' } });
                if (!response.ok) throw new Error(`Network response was not ok: ${response.statusText}`);
                displayDnsResults(await response.json());
            } catch (error) {
                displayError(dnsResultsContainer, error.message);
            }
        });
    }

    function displayDnsResults(data) {
        dnsResultsContainer.innerHTML = '';
        if (data.Status !== 0 || !data.Answer) {
            displayError(dnsResultsContainer, data.Comment || 'No records found or an error occurred.');
            return;
        }
        const card = createCard(`DNS Results for ${data.Question[0].name}`);
        const table = createTable(['Type', 'TTL', 'Data']);
        const tbody = table.querySelector('tbody');
        data.Answer.forEach(record => {
            const row = document.createElement('tr');
            row.innerHTML = `<td>${record.type}</td><td>${record.TTL}</td><td style="word-break: break-all;">${record.data}</td>`;
            tbody.appendChild(row);
        });
        card.body.appendChild(table);
        dnsResultsContainer.appendChild(card.element);
    }

    // --- IP/Subnet Calculator Logic ---
    const ipCalculatorForm = document.getElementById('ip-calculator-form');
    const ipResultsContainer = document.getElementById('ip-results-container');
    if (ipCalculatorForm) {
        ipCalculatorForm.addEventListener('submit', (event) => {
            event.preventDefault();
            const query = document.getElementById('ip-address').value;
            try {
                displayIpResults(calculateIpInfo(query));
            } catch (error) {
                displayError(ipResultsContainer, error.message);
            }
        });
    }

    function calculateIpInfo(cidr) {
        const [ipStr, prefixStr] = cidr.split('/');
        if (!prefixStr) throw new Error('Invalid CIDR format. Use IP/Prefix (e.g., 192.168.1.1/24).');
        const prefix = parseInt(prefixStr, 10);
        if (isNaN(prefix) || prefix < 0 || prefix > 32) throw new Error('Invalid prefix: must be 0-32.');
        const ipInt = ipToLong(ipStr);
        if (ipInt === null) throw new Error('Invalid IP address.');
        const subnetMask = (-1 << (32 - prefix)) >>> 0;
        const networkAddress = (ipInt & subnetMask) >>> 0;
        const broadcastAddress = (networkAddress | ~subnetMask) >>> 0;
        const hostBits = 32 - prefix;
        const totalHosts = Math.pow(2, hostBits);
        const usableHosts = totalHosts >= 2 ? totalHosts - 2 : 0;
        const firstHost = usableHosts > 0 ? networkAddress + 1 : broadcastAddress;
        const lastHost = usableHosts > 0 ? broadcastAddress - 1 : broadcastAddress;
        return { cidr, networkAddress: longToIp(networkAddress), broadcastAddress: longToIp(broadcastAddress), subnetMask: longToIp(subnetMask), wildcardMask: longToIp(~subnetMask), firstUsableHost: longToIp(firstHost), lastUsableHost: longToIp(lastHost), totalHosts, usableHosts };
    }

    function displayIpResults(data) {
        ipResultsContainer.innerHTML = '';
        const card = createCard(`Analysis for ${data.cidr}`);
        const list = document.createElement('dl');
        list.className = 'row';
        const items = { 'Network Address': data.networkAddress, 'Subnet Mask': data.subnetMask, 'Broadcast Address': data.broadcastAddress, 'First Usable Host': data.usableHosts > 0 ? data.firstUsableHost : 'N/A', 'Last Usable Host': data.usableHosts > 0 ? data.lastUsableHost : 'N/A', 'Total Hosts': data.totalHosts.toLocaleString(), 'Usable Hosts': data.usableHosts.toLocaleString(), 'Wildcard Mask': data.wildcardMask };
        for (const [key, value] of Object.entries(items)) {
            list.innerHTML += `<dt class="col-sm-4">${key}</dt><dd class="col-sm-8">${value}</dd>`;
        }
        card.body.appendChild(list);
        ipResultsContainer.appendChild(card.element);
    }

    // --- Security Headers Logic ---
    const securityHeadersForm = document.getElementById('security-headers-form');
    const headersResultsContainer = document.getElementById('headers-results-container');
    if (securityHeadersForm) {
        securityHeadersForm.addEventListener('submit', async (event) => {
            event.preventDefault();
            let url = document.getElementById('url-input').value;
            if (!url.startsWith('http')) url = 'https://' + url;
            document.getElementById('url-input').value = url;
            showLoading(headersResultsContainer);
            try {
                const response = await fetch(`https://corsproxy.io/?${encodeURIComponent(url)}`);
                if (!response.ok) throw new Error(`Proxy fetch failed: ${response.status}`);
                displayHeadersResults(response.headers, url);
            } catch (error) {
                displayError(headersResultsContainer, `Could not fetch headers. ${error.message}`);
            }
        });
    }

    function displayHeadersResults(headers, url) {
        headersResultsContainer.innerHTML = '';
        const card = createCard(`Header Analysis for ${url}`);
        const importantHeaders = ['content-security-policy', 'strict-transport-security', 'x-frame-options', 'x-content-type-options', 'referrer-policy', 'permissions-policy'];
        const foundHeaders = new Map([...headers.entries()].map(([k, v]) => [k.toLowerCase(), v]));
        const table = createTable(['Header', 'Value / Status']);
        const tbody = table.querySelector('tbody');
        importantHeaders.forEach(h => {
            const row = tbody.insertRow();
            row.innerHTML = `<td>${h}</td>`;
            const valueCell = row.insertCell();
            if (foundHeaders.has(h)) {
                row.className = 'table-success';
                valueCell.textContent = foundHeaders.get(h);
                valueCell.style.wordBreak = 'break-all';
            } else {
                row.className = 'table-warning';
                valueCell.textContent = 'Not set';
            }
        });
        card.body.innerHTML += `<p class="mt-3 small text-muted">Uses a public CORS proxy. <span class="badge bg-success">Green</span> = present, <span class="badge bg-warning text-dark">Yellow</span> = missing.</p>`;
        card.body.appendChild(table);
        headersResultsContainer.appendChild(card.element);
    }

    // --- IP & ASN Lookup Logic ---
    const ipAsnLookupForm = document.getElementById('ip-asn-lookup-form');
    const ipAsnResultsContainer = document.getElementById('ip-asn-results-container');
    if (ipAsnLookupForm) {
        ipAsnLookupForm.addEventListener('submit', async (event) => {
            event.preventDefault();
            const query = document.getElementById('ip-asn-input').value;
            const source = document.getElementById('ip-asn-source').value;
            showLoading(ipAsnResultsContainer);
            try {
                let data;
                if (source === 'ipwho.is') {
                    data = await fetchIpWhoIsInfo(query);
                } else {
                    data = await fetchIpApiComInfo(query);
                }
                displayIpAsnResults(data, source);
            } catch (error) {
                displayError(ipAsnResultsContainer, error.message);
            }
        });
    }

    async function fetchIpApiComInfo(query) {
        const apiFields = 'status,message,country,city,lat,lon,isp,org,as,query';
        const response = await fetch(`http://ip-api.com/json/${encodeURIComponent(query)}?fields=${apiFields}`);
        const data = await response.json();
        if (data.status === 'fail') throw new Error(data.message);
        return data;
    }

    async function fetchIpWhoIsInfo(query) {
        const response = await fetch(`https://ipwho.is/${encodeURIComponent(query)}`);
        const data = await response.json();
        if (!data.success) throw new Error(data.message);
        return data;
    }

    function displayIpAsnResults(data, source) {
        ipAsnResultsContainer.innerHTML = '';
        
        const normalized = {
            ip: data.query || data.ip,
            asn: data.as || data.asn,
            isp: data.isp,
            org: data.org || '',
            location: (data.city && data.country) ? `${data.city}, ${data.country}` : 'N/A',
            coordinates: (data.lat && data.lon) ? `${data.lat}, ${data.lon}` : 'N/A'
        };

        const card = createCard(`Lookup Results for ${normalized.ip}`);
        const list = document.createElement('dl');
        list.className = 'row';
        const items = { 'IP Address': normalized.ip, 'ASN': normalized.asn, 'ISP': normalized.isp, 'Organization': normalized.org, 'Location': normalized.location, 'Coordinates': normalized.coordinates };
        
        for (const [key, value] of Object.entries(items)) {
            if (value) list.innerHTML += `<dt class="col-sm-4">${key}</dt><dd class="col-sm-8">${value}</dd>`;
        }
        
        card.body.innerHTML += `<p class="mt-3 small text-muted">Data from ${source}.</p>`;
        card.body.appendChild(list);
        ipAsnResultsContainer.appendChild(card.element);
    }

    // --- HTTPS Latency Logic ---
    const httpsLatencyForm = document.getElementById('https-latency-form');
    const latencyResultsContainer = document.getElementById('latency-results-container');
    if (httpsLatencyForm) {
        httpsLatencyForm.addEventListener('submit', (event) => {
            event.preventDefault();
            let url = document.getElementById('latency-url-input').value;
            if (!url.startsWith('http')) url = 'https://' + url;
            document.getElementById('latency-url-input').value = url;
            showLoading(latencyResultsContainer);
            const observer = new PerformanceObserver((list) => {
                const entry = list.getEntries()[0];
                if (entry.name.includes('?cachebust=')) {
                    displayLatencyResults(entry, url);
                    observer.disconnect();
                }
            });
            observer.observe({ type: "resource", buffered: true });
            fetch(`${url}${url.includes('?') ? '&' : '?'}cachebust=${Date.now()}`, { mode: 'no-cors' }).catch(err => {
                displayError(latencyResultsContainer, `Could not fetch resource: ${err.message}`);
                observer.disconnect();
            });
        });
    }

    function displayLatencyResults(entry, url) {
        latencyResultsContainer.innerHTML = '';
        const card = createCard(`Latency for ${url}`);
        const timings = { 'DNS Lookup': entry.domainLookupEnd - entry.domainLookupStart, 'TCP Connection': entry.connectEnd - entry.connectStart, 'TLS Handshake': entry.secureConnectionStart > 0 ? entry.connectEnd - entry.secureConnectionStart : 0, 'Time to First Byte (TTFB)': entry.responseStart - entry.requestStart, 'Content Download': entry.responseEnd - entry.responseStart, 'Total Time': entry.duration };
        const list = document.createElement('dl');
        list.className = 'row';
        for (const [key, value] of Object.entries(timings)) {
            list.innerHTML += `<dt class="col-sm-4">${key}</dt><dd class="col-sm-8">${value.toFixed(2)} ms</dd>`;
        }
        card.body.appendChild(list);
        latencyResultsContainer.appendChild(card.element);
    }

    // --- Traceroute Visualizer Logic ---
    const tracerouteForm = document.getElementById('traceroute-visualizer-form');
    const tracerouteResultsContainer = document.getElementById('traceroute-results-container');
    if (tracerouteForm) {
        tracerouteForm.addEventListener('submit', async (event) => {
            event.preventDefault();
            const rawData = document.getElementById('traceroute-input').value;
            const hops = parseTraceroute(rawData);
            if (hops.length === 0) {
                displayError(tracerouteResultsContainer, 'Could not parse any hops. Please paste valid traceroute/tracert output.');
                return;
            }
            showLoading(tracerouteResultsContainer);
            await visualizeTraceroute(hops);
        });
    }
    
    function parseTraceroute(data) {
        const lines = data.trim().split('\n');
        const ipRegex = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/; 
        const hops = [];
        for (const line of lines) {
            const match = line.match(ipRegex);
            if (match) {
                hops.push({ ip: match[0], originalLine: line.trim() });
            }
        }
        return hops;
    }

    async function visualizeTraceroute(hops) {
        tracerouteResultsContainer.innerHTML = '';
        const ipInfoCache = new Map();
        let lastAsn = null;

        for (let i = 0; i < hops.length; i++) {
            const hop = hops[i];
            let info;
            if (ipInfoCache.has(hop.ip)) {
                info = ipInfoCache.get(hop.ip);
            } else {
                try {
                    await new Promise(res => setTimeout(res, 600)); // Rate-limit API calls
                    info = await fetchIpApiComInfo(hop.ip); // Using the primary API for this
                    ipInfoCache.set(hop.ip, info);
                } catch (error) {
                    info = { as: 'N/A', org: 'Error fetching info', query: hop.ip };
                }
            }
            
            const currentAsn = info.as || 'Private/Unknown ASN';
            if (currentAsn !== lastAsn) {
                const asnCard = createCard(currentAsn);
                asnCard.body.querySelector('.card-title').classList.add('mb-2');
                if (info.org) {
                    const orgText = document.createElement('h6');
                    orgText.className = 'card-subtitle mb-2 text-muted';
                    orgText.textContent = info.org;
                    asnCard.body.insertBefore(orgText, asnCard.body.childNodes[1]);
                }
                tracerouteResultsContainer.appendChild(asnCard.element);
                lastAsn = currentAsn;
            }

            const currentAsnCard = tracerouteResultsContainer.lastChild;
            const hopElement = document.createElement('div');
            hopElement.className = 'p-2 border-top';
            hopElement.textContent = `${i + 1}: ${hop.originalLine}`;
            currentAsnCard.querySelector('.card-body').appendChild(hopElement);
        }
    }


    // --- Utility Functions ---
    function ipToLong(ip) {
        const parts = ip.split('.');
        if (parts.length !== 4) return null;
        return parts.reduce((acc, part) => (acc * 256) + parseInt(part, 10), 0) >>> 0;
    }

    function longToIp(long) {
        return `${(long >>> 24)}.${(long >> 16 & 255)}.${(long >> 8 & 255)}.${(long & 255)}`;
    }

    function showLoading(container) {
        if(container) container.innerHTML = `<div class="d-flex justify-content-center"><div class="spinner-border" role="status"><span class="visually-hidden">Loading...</span></div></div>`;
    }

    function displayError(container, message) {
        if(container) container.innerHTML = `<div class="alert alert-danger" role="alert"><strong>Error:</strong> ${message}</div>`;
    }

    function createCard(titleText) {
        const card = document.createElement('div');
        card.className = 'card bg-dark text-white mb-3';
        const cardBody = document.createElement('div');
        cardBody.className = 'card-body';
        const title = document.createElement('h5');
        title.className = 'card-title';
        title.textContent = titleText;
        cardBody.appendChild(title);
        card.appendChild(cardBody);
        return { element: card, body: cardBody };
    }

    function createTable(headers) {
        const table = document.createElement('table');
        table.className = 'table table-dark table-striped';
        const thead = table.createTHead();
        const tr = thead.insertRow();
        headers.forEach(h => {
            const th = document.createElement('th');
            th.scope = 'col';
            th.textContent = h;
            tr.appendChild(th);
        });
        table.appendChild(document.createElement('tbody'));
        return table;
    }
});