const currentHostname = window.location.hostname;
let apiHost;
if (currentHostname === "localhost" || currentHostname === "127.0.0.1") {
    apiHost = '127.0.0.1';
} else {
    apiHost = currentHostname;
}
const API_BASE_URL = `http://${apiHost}:5001`;
console.log(`[ConfigJS] API_BASE_URL 已自动设置为: ${API_BASE_URL}`);