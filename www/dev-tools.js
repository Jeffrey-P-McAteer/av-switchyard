(() => {
    const localhostHosts = new Set([
        "localhost",
        "127.0.0.1",
        "::1",
    ]);

    if (!localhostHosts.has(window.location.hostname)) {
        return;
    }

    console.log("Development mode: page will reload every 16 seconds.");

    setTimeout(() => {
        window.location.reload();
    }, 16_000);
})();

