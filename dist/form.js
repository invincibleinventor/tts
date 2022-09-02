(() => {
  var e,
    t,
    n,
    r,
    i = {
      98: function (e, t) {
        var n = "undefined" != typeof self ? self : this,
          r = (function () {
            function e() {
              (this.fetch = !1), (this.DOMException = n.DOMException);
            }
            return (e.prototype = n), new e();
          })();
        !(function (e) {
          !(function (t) {
            var n = "URLSearchParams" in e,
              r = "Symbol" in e && "iterator" in Symbol,
              i =
                "FileReader" in e &&
                "Blob" in e &&
                (function () {
                  try {
                    return new Blob(), !0;
                  } catch (e) {
                    return !1;
                  }
                })(),
              o = "FormData" in e,
              s = "ArrayBuffer" in e;
            if (s)
              var a = [
                  "[object Int8Array]",
                  "[object Uint8Array]",
                  "[object Uint8ClampedArray]",
                  "[object Int16Array]",
                  "[object Uint16Array]",
                  "[object Int32Array]",
                  "[object Uint32Array]",
                  "[object Float32Array]",
                  "[object Float64Array]",
                ],
                c =
                  ArrayBuffer.isView ||
                  function (e) {
                    return (
                      e && a.indexOf(Object.prototype.toString.call(e)) > -1
                    );
                  };
            function l(e) {
              if (
                ("string" != typeof e && (e = String(e)),
                /[^a-z0-9\-#$%&'*+.^_`|~]/i.test(e))
              )
                throw new TypeError("Invalid character in header field name");
              return e.toLowerCase();
            }
            function A(e) {
              return "string" != typeof e && (e = String(e)), e;
            }
            function d(e) {
              var t = {
                next: function () {
                  var t = e.shift();
                  return { done: void 0 === t, value: t };
                },
              };
              return (
                r &&
                  (t[Symbol.iterator] = function () {
                    return t;
                  }),
                t
              );
            }
            function u(e) {
              (this.map = {}),
                e instanceof u
                  ? e.forEach(function (e, t) {
                      this.append(t, e);
                    }, this)
                  : Array.isArray(e)
                  ? e.forEach(function (e) {
                      this.append(e[0], e[1]);
                    }, this)
                  : e &&
                    Object.getOwnPropertyNames(e).forEach(function (t) {
                      this.append(t, e[t]);
                    }, this);
            }
            function h(e) {
              if (e.bodyUsed)
                return Promise.reject(new TypeError("Already read"));
              e.bodyUsed = !0;
            }
            function g(e) {
              return new Promise(function (t, n) {
                (e.onload = function () {
                  t(e.result);
                }),
                  (e.onerror = function () {
                    n(e.error);
                  });
              });
            }
            function p(e) {
              var t = new FileReader(),
                n = g(t);
              return t.readAsArrayBuffer(e), n;
            }
            function m(e) {
              if (e.slice) return e.slice(0);
              var t = new Uint8Array(e.byteLength);
              return t.set(new Uint8Array(e)), t.buffer;
            }
            function w() {
              return (
                (this.bodyUsed = !1),
                (this._initBody = function (e) {
                  var t;
                  (this._bodyInit = e),
                    e
                      ? "string" == typeof e
                        ? (this._bodyText = e)
                        : i && Blob.prototype.isPrototypeOf(e)
                        ? (this._bodyBlob = e)
                        : o && FormData.prototype.isPrototypeOf(e)
                        ? (this._bodyFormData = e)
                        : n && URLSearchParams.prototype.isPrototypeOf(e)
                        ? (this._bodyText = e.toString())
                        : s &&
                          i &&
                          (t = e) &&
                          DataView.prototype.isPrototypeOf(t)
                        ? ((this._bodyArrayBuffer = m(e.buffer)),
                          (this._bodyInit = new Blob([this._bodyArrayBuffer])))
                        : s && (ArrayBuffer.prototype.isPrototypeOf(e) || c(e))
                        ? (this._bodyArrayBuffer = m(e))
                        : (this._bodyText = e =
                            Object.prototype.toString.call(e))
                      : (this._bodyText = ""),
                    this.headers.get("content-type") ||
                      ("string" == typeof e
                        ? this.headers.set(
                            "content-type",
                            "text/plain;charset=UTF-8"
                          )
                        : this._bodyBlob && this._bodyBlob.type
                        ? this.headers.set("content-type", this._bodyBlob.type)
                        : n &&
                          URLSearchParams.prototype.isPrototypeOf(e) &&
                          this.headers.set(
                            "content-type",
                            "application/x-www-form-urlencoded;charset=UTF-8"
                          ));
                }),
                i &&
                  ((this.blob = function () {
                    var e = h(this);
                    if (e) return e;
                    if (this._bodyBlob) return Promise.resolve(this._bodyBlob);
                    if (this._bodyArrayBuffer)
                      return Promise.resolve(new Blob([this._bodyArrayBuffer]));
                    if (this._bodyFormData)
                      throw new Error("could not read FormData body as blob");
                    return Promise.resolve(new Blob([this._bodyText]));
                  }),
                  (this.arrayBuffer = function () {
                    return this._bodyArrayBuffer
                      ? h(this) || Promise.resolve(this._bodyArrayBuffer)
                      : this.blob().then(p);
                  })),
                (this.text = function () {
                  var e,
                    t,
                    n,
                    r = h(this);
                  if (r) return r;
                  if (this._bodyBlob)
                    return (
                      (e = this._bodyBlob),
                      (n = g((t = new FileReader()))),
                      t.readAsText(e),
                      n
                    );
                  if (this._bodyArrayBuffer)
                    return Promise.resolve(
                      (function (e) {
                        for (
                          var t = new Uint8Array(e),
                            n = new Array(t.length),
                            r = 0;
                          r < t.length;
                          r++
                        )
                          n[r] = String.fromCharCode(t[r]);
                        return n.join("");
                      })(this._bodyArrayBuffer)
                    );
                  if (this._bodyFormData)
                    throw new Error("could not read FormData body as text");
                  return Promise.resolve(this._bodyText);
                }),
                o &&
                  (this.formData = function () {
                    return this.text().then(y);
                  }),
                (this.json = function () {
                  return this.text().then(JSON.parse);
                }),
                this
              );
            }
            (u.prototype.append = function (e, t) {
              (e = l(e)), (t = A(t));
              var n = this.map[e];
              this.map[e] = n ? n + ", " + t : t;
            }),
              (u.prototype.delete = function (e) {
                delete this.map[l(e)];
              }),
              (u.prototype.get = function (e) {
                return (e = l(e)), this.has(e) ? this.map[e] : null;
              }),
              (u.prototype.has = function (e) {
                return this.map.hasOwnProperty(l(e));
              }),
              (u.prototype.set = function (e, t) {
                this.map[l(e)] = A(t);
              }),
              (u.prototype.forEach = function (e, t) {
                for (var n in this.map)
                  this.map.hasOwnProperty(n) && e.call(t, this.map[n], n, this);
              }),
              (u.prototype.keys = function () {
                var e = [];
                return (
                  this.forEach(function (t, n) {
                    e.push(n);
                  }),
                  d(e)
                );
              }),
              (u.prototype.values = function () {
                var e = [];
                return (
                  this.forEach(function (t) {
                    e.push(t);
                  }),
                  d(e)
                );
              }),
              (u.prototype.entries = function () {
                var e = [];
                return (
                  this.forEach(function (t, n) {
                    e.push([n, t]);
                  }),
                  d(e)
                );
              }),
              r && (u.prototype[Symbol.iterator] = u.prototype.entries);
            var E = ["DELETE", "GET", "HEAD", "OPTIONS", "POST", "PUT"];
            function f(e, t) {
              var n,
                r,
                i = (t = t || {}).body;
              if (e instanceof f) {
                if (e.bodyUsed) throw new TypeError("Already read");
                (this.url = e.url),
                  (this.credentials = e.credentials),
                  t.headers || (this.headers = new u(e.headers)),
                  (this.method = e.method),
                  (this.mode = e.mode),
                  (this.signal = e.signal),
                  i ||
                    null == e._bodyInit ||
                    ((i = e._bodyInit), (e.bodyUsed = !0));
              } else this.url = String(e);
              if (
                ((this.credentials =
                  t.credentials || this.credentials || "same-origin"),
                (!t.headers && this.headers) ||
                  (this.headers = new u(t.headers)),
                (this.method =
                  ((r = (n = t.method || this.method || "GET").toUpperCase()),
                  E.indexOf(r) > -1 ? r : n)),
                (this.mode = t.mode || this.mode || null),
                (this.signal = t.signal || this.signal),
                (this.referrer = null),
                ("GET" === this.method || "HEAD" === this.method) && i)
              )
                throw new TypeError(
                  "Body not allowed for GET or HEAD requests"
                );
              this._initBody(i);
            }
            function y(e) {
              var t = new FormData();
              return (
                e
                  .trim()
                  .split("&")
                  .forEach(function (e) {
                    if (e) {
                      var n = e.split("="),
                        r = n.shift().replace(/\+/g, " "),
                        i = n.join("=").replace(/\+/g, " ");
                      t.append(decodeURIComponent(r), decodeURIComponent(i));
                    }
                  }),
                t
              );
            }
            function b(e, t) {
              t || (t = {}),
                (this.type = "default"),
                (this.status = void 0 === t.status ? 200 : t.status),
                (this.ok = this.status >= 200 && this.status < 300),
                (this.statusText = "statusText" in t ? t.statusText : "OK"),
                (this.headers = new u(t.headers)),
                (this.url = t.url || ""),
                this._initBody(e);
            }
            (f.prototype.clone = function () {
              return new f(this, { body: this._bodyInit });
            }),
              w.call(f.prototype),
              w.call(b.prototype),
              (b.prototype.clone = function () {
                return new b(this._bodyInit, {
                  status: this.status,
                  statusText: this.statusText,
                  headers: new u(this.headers),
                  url: this.url,
                });
              }),
              (b.error = function () {
                var e = new b(null, { status: 0, statusText: "" });
                return (e.type = "error"), e;
              });
            var C = [301, 302, 303, 307, 308];
            (b.redirect = function (e, t) {
              if (-1 === C.indexOf(t))
                throw new RangeError("Invalid status code");
              return new b(null, { status: t, headers: { location: e } });
            }),
              (t.DOMException = e.DOMException);
            try {
              new t.DOMException();
            } catch (e) {
              (t.DOMException = function (e, t) {
                (this.message = e), (this.name = t);
                var n = Error(e);
                this.stack = n.stack;
              }),
                (t.DOMException.prototype = Object.create(Error.prototype)),
                (t.DOMException.prototype.constructor = t.DOMException);
            }
            function M(e, n) {
              return new Promise(function (r, o) {
                var s = new f(e, n);
                if (s.signal && s.signal.aborted)
                  return o(new t.DOMException("Aborted", "AbortError"));
                var a = new XMLHttpRequest();
                function c() {
                  a.abort();
                }
                (a.onload = function () {
                  var e,
                    t,
                    n = {
                      status: a.status,
                      statusText: a.statusText,
                      headers:
                        ((e = a.getAllResponseHeaders() || ""),
                        (t = new u()),
                        e
                          .replace(/\r?\n[\t ]+/g, " ")
                          .split(/\r?\n/)
                          .forEach(function (e) {
                            var n = e.split(":"),
                              r = n.shift().trim();
                            if (r) {
                              var i = n.join(":").trim();
                              t.append(r, i);
                            }
                          }),
                        t),
                    };
                  n.url =
                    "responseURL" in a
                      ? a.responseURL
                      : n.headers.get("X-Request-URL");
                  var i = "response" in a ? a.response : a.responseText;
                  r(new b(i, n));
                }),
                  (a.onerror = function () {
                    o(new TypeError("Network request failed"));
                  }),
                  (a.ontimeout = function () {
                    o(new TypeError("Network request failed"));
                  }),
                  (a.onabort = function () {
                    o(new t.DOMException("Aborted", "AbortError"));
                  }),
                  a.open(s.method, s.url, !0),
                  "include" === s.credentials
                    ? (a.withCredentials = !0)
                    : "omit" === s.credentials && (a.withCredentials = !1),
                  "responseType" in a && i && (a.responseType = "blob"),
                  s.headers.forEach(function (e, t) {
                    a.setRequestHeader(t, e);
                  }),
                  s.signal &&
                    (s.signal.addEventListener("abort", c),
                    (a.onreadystatechange = function () {
                      4 === a.readyState &&
                        s.signal.removeEventListener("abort", c);
                    })),
                  a.send(void 0 === s._bodyInit ? null : s._bodyInit);
              });
            }
            (M.polyfill = !0),
              e.fetch ||
                ((e.fetch = M),
                (e.Headers = u),
                (e.Request = f),
                (e.Response = b)),
              (t.Headers = u),
              (t.Request = f),
              (t.Response = b),
              (t.fetch = M),
              Object.defineProperty(t, "__esModule", { value: !0 });
          })({});
        })(r),
          (r.fetch.ponyfill = !0),
          delete r.fetch.polyfill;
        var i = r;
        ((t = i.fetch).default = i.fetch),
          (t.fetch = i.fetch),
          (t.Headers = i.Headers),
          (t.Request = i.Request),
          (t.Response = i.Response),
          (e.exports = t);
      },
      265: (e, t, n) => {
        "use strict";
        n.d(t, { Z: () => E });
        var r = n(537),
          i = n.n(r),
          o = n(645),
          s = n.n(o),
          a = n(667),
          c = n.n(a),
          l = new URL(n(909), n.b),
          A = new URL(n(133), n.b),
          d = new URL(n(601), n.b),
          u = new URL(n(686), n.b),
          h = s()(i()),
          g = c()(l),
          p = c()(A),
          m = c()(d),
          w = c()(u);
        h.push([
          e.id,
          "/*\n! tailwindcss v3.1.8 | MIT License | https://tailwindcss.com\n*/\n\n/*\n1. Prevent padding and border from affecting element width. (https://github.com/mozdevs/cssremedy/issues/4)\n2. Allow adding a border to an element by just adding a border-width. (https://github.com/tailwindcss/tailwindcss/pull/116)\n*/\n\n*,\n::before,\n::after {\n  box-sizing: border-box;\n  /* 1 */\n  border-width: 0;\n  /* 2 */\n  border-style: solid;\n  /* 2 */\n  border-color: #e5e7eb;\n  /* 2 */\n}\n\n::before,\n::after {\n  --tw-content: '';\n}\n\n/*\n1. Use a consistent sensible line-height in all browsers.\n2. Prevent adjustments of font size after orientation changes in iOS.\n3. Use a more readable tab size.\n4. Use the user's configured `sans` font-family by default.\n*/\n\nhtml {\n  line-height: 1.5;\n  /* 1 */\n  -webkit-text-size-adjust: 100%;\n  /* 2 */\n  -moz-tab-size: 4;\n  /* 3 */\n  -o-tab-size: 4;\n     tab-size: 4;\n  /* 3 */\n  font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, Noto Sans, sans-serif, BlinkMacSystemFont, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, \"Noto Sans\", sans-serif, \"Apple Color Emoji\", \"Segoe UI Emoji\", \"Segoe UI Symbol\", \"Noto Color Emoji\";\n  /* 4 */\n}\n\n/*\n1. Remove the margin in all browsers.\n2. Inherit line-height from `html` so users can set them as a class directly on the `html` element.\n*/\n\nbody {\n  margin: 0;\n  /* 1 */\n  line-height: inherit;\n  /* 2 */\n}\n\n/*\n1. Add the correct height in Firefox.\n2. Correct the inheritance of border color in Firefox. (https://bugzilla.mozilla.org/show_bug.cgi?id=190655)\n3. Ensure horizontal rules are visible by default.\n*/\n\nhr {\n  height: 0;\n  /* 1 */\n  color: inherit;\n  /* 2 */\n  border-top-width: 1px;\n  /* 3 */\n}\n\n/*\nAdd the correct text decoration in Chrome, Edge, and Safari.\n*/\n\nabbr:where([title]) {\n  -webkit-text-decoration: underline dotted;\n          text-decoration: underline;\n          -webkit-text-decoration: underline dotted currentColor;\n                  text-decoration: underline dotted currentColor;\n}\n\n/*\nRemove the default font size and weight for headings.\n*/\n\nh1,\nh2,\nh3,\nh4,\nh5,\nh6 {\n  font-size: inherit;\n  font-weight: inherit;\n}\n\n/*\nReset links to optimize for opt-in styling instead of opt-out.\n*/\n\na {\n  color: inherit;\n  text-decoration: inherit;\n}\n\n/*\nAdd the correct font weight in Edge and Safari.\n*/\n\nb,\nstrong {\n  font-weight: bolder;\n}\n\n/*\n1. Use the user's configured `mono` font family by default.\n2. Correct the odd `em` font sizing in all browsers.\n*/\n\ncode,\nkbd,\nsamp,\npre {\n  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, \"Liberation Mono\", \"Courier New\", monospace;\n  /* 1 */\n  font-size: 1em;\n  /* 2 */\n}\n\n/*\nAdd the correct font size in all browsers.\n*/\n\nsmall {\n  font-size: 80%;\n}\n\n/*\nPrevent `sub` and `sup` elements from affecting the line height in all browsers.\n*/\n\nsub,\nsup {\n  font-size: 75%;\n  line-height: 0;\n  position: relative;\n  vertical-align: baseline;\n}\n\nsub {\n  bottom: -0.25em;\n}\n\nsup {\n  top: -0.5em;\n}\n\n/*\n1. Remove text indentation from table contents in Chrome and Safari. (https://bugs.chromium.org/p/chromium/issues/detail?id=999088, https://bugs.webkit.org/show_bug.cgi?id=201297)\n2. Correct table border color inheritance in all Chrome and Safari. (https://bugs.chromium.org/p/chromium/issues/detail?id=935729, https://bugs.webkit.org/show_bug.cgi?id=195016)\n3. Remove gaps between table borders by default.\n*/\n\ntable {\n  text-indent: 0;\n  /* 1 */\n  border-color: inherit;\n  /* 2 */\n  border-collapse: collapse;\n  /* 3 */\n}\n\n/*\n1. Change the font styles in all browsers.\n2. Remove the margin in Firefox and Safari.\n3. Remove default padding in all browsers.\n*/\n\nbutton,\ninput,\noptgroup,\nselect,\ntextarea {\n  font-family: inherit;\n  /* 1 */\n  font-size: 100%;\n  /* 1 */\n  font-weight: inherit;\n  /* 1 */\n  line-height: inherit;\n  /* 1 */\n  color: inherit;\n  /* 1 */\n  margin: 0;\n  /* 2 */\n  padding: 0;\n  /* 3 */\n}\n\n/*\nRemove the inheritance of text transform in Edge and Firefox.\n*/\n\nbutton,\nselect {\n  text-transform: none;\n}\n\n/*\n1. Correct the inability to style clickable types in iOS and Safari.\n2. Remove default button styles.\n*/\n\nbutton,\n[type='button'],\n[type='reset'],\n[type='submit'] {\n  -webkit-appearance: button;\n  /* 1 */\n  background-color: transparent;\n  /* 2 */\n  background-image: none;\n  /* 2 */\n}\n\n/*\nUse the modern Firefox focus style for all focusable elements.\n*/\n\n:-moz-focusring {\n  outline: auto;\n}\n\n/*\nRemove the additional `:invalid` styles in Firefox. (https://github.com/mozilla/gecko-dev/blob/2f9eacd9d3d995c937b4251a5557d95d494c9be1/layout/style/res/forms.css#L728-L737)\n*/\n\n:-moz-ui-invalid {\n  box-shadow: none;\n}\n\n/*\nAdd the correct vertical alignment in Chrome and Firefox.\n*/\n\nprogress {\n  vertical-align: baseline;\n}\n\n/*\nCorrect the cursor style of increment and decrement buttons in Safari.\n*/\n\n::-webkit-inner-spin-button,\n::-webkit-outer-spin-button {\n  height: auto;\n}\n\n/*\n1. Correct the odd appearance in Chrome and Safari.\n2. Correct the outline style in Safari.\n*/\n\n[type='search'] {\n  -webkit-appearance: textfield;\n  /* 1 */\n  outline-offset: -2px;\n  /* 2 */\n}\n\n/*\nRemove the inner padding in Chrome and Safari on macOS.\n*/\n\n::-webkit-search-decoration {\n  -webkit-appearance: none;\n}\n\n/*\n1. Correct the inability to style clickable types in iOS and Safari.\n2. Change font properties to `inherit` in Safari.\n*/\n\n::-webkit-file-upload-button {\n  -webkit-appearance: button;\n  /* 1 */\n  font: inherit;\n  /* 2 */\n}\n\n/*\nAdd the correct display in Chrome and Safari.\n*/\n\nsummary {\n  display: list-item;\n}\n\n/*\nRemoves the default spacing and border for appropriate elements.\n*/\n\nblockquote,\ndl,\ndd,\nh1,\nh2,\nh3,\nh4,\nh5,\nh6,\nhr,\nfigure,\np,\npre {\n  margin: 0;\n}\n\nfieldset {\n  margin: 0;\n  padding: 0;\n}\n\nlegend {\n  padding: 0;\n}\n\nol,\nul,\nmenu {\n  list-style: none;\n  margin: 0;\n  padding: 0;\n}\n\n/*\nPrevent resizing textareas horizontally by default.\n*/\n\ntextarea {\n  resize: vertical;\n}\n\n/*\n1. Reset the default placeholder opacity in Firefox. (https://github.com/tailwindlabs/tailwindcss/issues/3300)\n2. Set the default placeholder color to the user's configured gray 400 color.\n*/\n\ninput::-moz-placeholder, textarea::-moz-placeholder {\n  opacity: 1;\n  /* 1 */\n  color: #9ca3af;\n  /* 2 */\n}\n\ninput::placeholder,\ntextarea::placeholder {\n  opacity: 1;\n  /* 1 */\n  color: #9ca3af;\n  /* 2 */\n}\n\n/*\nSet the default cursor for buttons.\n*/\n\nbutton,\n[role=\"button\"] {\n  cursor: pointer;\n}\n\n/*\nMake sure disabled buttons don't get the pointer cursor.\n*/\n\n:disabled {\n  cursor: default;\n}\n\n/*\n1. Make replaced elements `display: block` by default. (https://github.com/mozdevs/cssremedy/issues/14)\n2. Add `vertical-align: middle` to align replaced elements more sensibly by default. (https://github.com/jensimmons/cssremedy/issues/14#issuecomment-634934210)\n   This can trigger a poorly considered lint error in some tools but is included by design.\n*/\n\nimg,\nsvg,\nvideo,\ncanvas,\naudio,\niframe,\nembed,\nobject {\n  display: block;\n  /* 1 */\n  vertical-align: middle;\n  /* 2 */\n}\n\n/*\nConstrain images and videos to the parent width and preserve their intrinsic aspect ratio. (https://github.com/mozdevs/cssremedy/issues/14)\n*/\n\nimg,\nvideo {\n  max-width: 100%;\n  height: auto;\n}\n\n[type='text'],[type='email'],[type='url'],[type='password'],[type='number'],[type='date'],[type='datetime-local'],[type='month'],[type='search'],[type='tel'],[type='time'],[type='week'],[multiple],textarea,select {\n  -webkit-appearance: none;\n     -moz-appearance: none;\n          appearance: none;\n  background-color: #fff;\n  border-color: #6b7280;\n  border-width: 1px;\n  border-radius: 0px;\n  padding-top: 0.5rem;\n  padding-right: 0.75rem;\n  padding-bottom: 0.5rem;\n  padding-left: 0.75rem;\n  font-size: 1rem;\n  line-height: 1.5rem;\n  --tw-shadow: 0 0 rgba(0,0,0,0);\n}\n\n[type='text']:focus, [type='email']:focus, [type='url']:focus, [type='password']:focus, [type='number']:focus, [type='date']:focus, [type='datetime-local']:focus, [type='month']:focus, [type='search']:focus, [type='tel']:focus, [type='time']:focus, [type='week']:focus, [multiple]:focus, textarea:focus, select:focus {\n  outline: 2px solid transparent;\n  outline-offset: 2px;\n  --tw-ring-inset: var(--tw-empty,/*!*/ /*!*/);\n  --tw-ring-offset-width: 0px;\n  --tw-ring-offset-color: #fff;\n  --tw-ring-color: #2563eb;\n  --tw-ring-offset-shadow: var(--tw-ring-inset) 0 0 0 var(--tw-ring-offset-width) var(--tw-ring-offset-color);\n  --tw-ring-shadow: var(--tw-ring-inset) 0 0 0 calc(1px + var(--tw-ring-offset-width)) var(--tw-ring-color);\n  box-shadow: var(--tw-ring-offset-shadow), var(--tw-ring-shadow), var(--tw-shadow);\n  border-color: #2563eb;\n}\n\ninput::-moz-placeholder, textarea::-moz-placeholder {\n  color: #6b7280;\n  opacity: 1;\n}\n\ninput::placeholder,textarea::placeholder {\n  color: #6b7280;\n  opacity: 1;\n}\n\n::-webkit-datetime-edit-fields-wrapper {\n  padding: 0;\n}\n\n::-webkit-date-and-time-value {\n  min-height: 1.5em;\n}\n\n::-webkit-datetime-edit,::-webkit-datetime-edit-year-field,::-webkit-datetime-edit-month-field,::-webkit-datetime-edit-day-field,::-webkit-datetime-edit-hour-field,::-webkit-datetime-edit-minute-field,::-webkit-datetime-edit-second-field,::-webkit-datetime-edit-millisecond-field,::-webkit-datetime-edit-meridiem-field {\n  padding-top: 0;\n  padding-bottom: 0;\n}\n\nselect {\n  background-image: url(" +
            g +
            ");\n  background-position: right 0.5rem center;\n  background-repeat: no-repeat;\n  background-size: 1.5em 1.5em;\n  padding-right: 2.5rem;\n  -webkit-print-color-adjust: exact;\n     color-adjust: exact;\n          print-color-adjust: exact;\n}\n\n[multiple] {\n  background-image: none;\n  background-image: initial;\n  background-position: 0 0;\n  background-position: initial;\n  background-repeat: repeat;\n  background-repeat: initial;\n  background-size: auto auto;\n  background-size: initial;\n  padding-right: 0.75rem;\n  -webkit-print-color-adjust: unset;\n     color-adjust: initial;\n          print-color-adjust: inherit;\n}\n\n[type='checkbox'],[type='radio'] {\n  -webkit-appearance: none;\n     -moz-appearance: none;\n          appearance: none;\n  padding: 0;\n  -webkit-print-color-adjust: exact;\n     color-adjust: exact;\n          print-color-adjust: exact;\n  display: inline-block;\n  vertical-align: middle;\n  background-origin: border-box;\n  -webkit-user-select: none;\n     -moz-user-select: none;\n          user-select: none;\n  flex-shrink: 0;\n  height: 1rem;\n  width: 1rem;\n  color: #2563eb;\n  background-color: #fff;\n  border-color: #6b7280;\n  border-width: 1px;\n  --tw-shadow: 0 0 rgba(0,0,0,0);\n}\n\n[type='checkbox'] {\n  border-radius: 0px;\n}\n\n[type='radio'] {\n  border-radius: 100%;\n}\n\n[type='checkbox']:focus,[type='radio']:focus {\n  outline: 2px solid transparent;\n  outline-offset: 2px;\n  --tw-ring-inset: var(--tw-empty,/*!*/ /*!*/);\n  --tw-ring-offset-width: 2px;\n  --tw-ring-offset-color: #fff;\n  --tw-ring-color: #2563eb;\n  --tw-ring-offset-shadow: var(--tw-ring-inset) 0 0 0 var(--tw-ring-offset-width) var(--tw-ring-offset-color);\n  --tw-ring-shadow: var(--tw-ring-inset) 0 0 0 calc(2px + var(--tw-ring-offset-width)) var(--tw-ring-color);\n  box-shadow: var(--tw-ring-offset-shadow), var(--tw-ring-shadow), var(--tw-shadow);\n}\n\n[type='checkbox']:checked,[type='radio']:checked {\n  border-color: transparent;\n  background-color: currentColor;\n  background-size: 100% 100%;\n  background-position: center;\n  background-repeat: no-repeat;\n}\n\n[type='checkbox']:checked {\n  background-image: url(" +
            p +
            ");\n}\n\n[type='radio']:checked {\n  background-image: url(" +
            m +
            ");\n}\n\n[type='checkbox']:checked:hover,[type='checkbox']:checked:focus,[type='radio']:checked:hover,[type='radio']:checked:focus {\n  border-color: transparent;\n  background-color: currentColor;\n}\n\n[type='checkbox']:indeterminate {\n  background-image: url(" +
            w +
            ");\n  border-color: transparent;\n  background-color: currentColor;\n  background-size: 100% 100%;\n  background-position: center;\n  background-repeat: no-repeat;\n}\n\n[type='checkbox']:indeterminate:hover,[type='checkbox']:indeterminate:focus {\n  border-color: transparent;\n  background-color: currentColor;\n}\n\n[type='file'] {\n  background: transparent none repeat 0 0 / auto auto padding-box border-box scroll;\n  background: initial;\n  border-color: inherit;\n  border-width: 0;\n  border-radius: 0;\n  padding: 0;\n  font-size: inherit;\n  line-height: inherit;\n}\n\n[type='file']:focus {\n  outline: 1px solid ButtonText;\n  outline: 1px auto -webkit-focus-ring-color;\n}\n\n*, ::before, ::after {\n  --tw-border-spacing-x: 0;\n  --tw-border-spacing-y: 0;\n  --tw-translate-x: 0;\n  --tw-translate-y: 0;\n  --tw-rotate: 0;\n  --tw-skew-x: 0;\n  --tw-skew-y: 0;\n  --tw-scale-x: 1;\n  --tw-scale-y: 1;\n  --tw-pan-x:  ;\n  --tw-pan-y:  ;\n  --tw-pinch-zoom:  ;\n  --tw-scroll-snap-strictness: proximity;\n  --tw-ordinal:  ;\n  --tw-slashed-zero:  ;\n  --tw-numeric-figure:  ;\n  --tw-numeric-spacing:  ;\n  --tw-numeric-fraction:  ;\n  --tw-ring-inset:  ;\n  --tw-ring-offset-width: 0px;\n  --tw-ring-offset-color: #fff;\n  --tw-ring-color: rgba(59, 130, 246, 0.5);\n  --tw-ring-offset-shadow: 0 0 rgba(0,0,0,0);\n  --tw-ring-shadow: 0 0 rgba(0,0,0,0);\n  --tw-shadow: 0 0 rgba(0,0,0,0);\n  --tw-shadow-colored: 0 0 rgba(0,0,0,0);\n  --tw-blur:  ;\n  --tw-brightness:  ;\n  --tw-contrast:  ;\n  --tw-grayscale:  ;\n  --tw-hue-rotate:  ;\n  --tw-invert:  ;\n  --tw-saturate:  ;\n  --tw-sepia:  ;\n  --tw-drop-shadow:  ;\n  --tw-backdrop-blur:  ;\n  --tw-backdrop-brightness:  ;\n  --tw-backdrop-contrast:  ;\n  --tw-backdrop-grayscale:  ;\n  --tw-backdrop-hue-rotate:  ;\n  --tw-backdrop-invert:  ;\n  --tw-backdrop-opacity:  ;\n  --tw-backdrop-saturate:  ;\n  --tw-backdrop-sepia:  ;\n}\n\n::-webkit-backdrop {\n  --tw-border-spacing-x: 0;\n  --tw-border-spacing-y: 0;\n  --tw-translate-x: 0;\n  --tw-translate-y: 0;\n  --tw-rotate: 0;\n  --tw-skew-x: 0;\n  --tw-skew-y: 0;\n  --tw-scale-x: 1;\n  --tw-scale-y: 1;\n  --tw-pan-x:  ;\n  --tw-pan-y:  ;\n  --tw-pinch-zoom:  ;\n  --tw-scroll-snap-strictness: proximity;\n  --tw-ordinal:  ;\n  --tw-slashed-zero:  ;\n  --tw-numeric-figure:  ;\n  --tw-numeric-spacing:  ;\n  --tw-numeric-fraction:  ;\n  --tw-ring-inset:  ;\n  --tw-ring-offset-width: 0px;\n  --tw-ring-offset-color: #fff;\n  --tw-ring-color: rgba(59, 130, 246, 0.5);\n  --tw-ring-offset-shadow: 0 0 rgba(0,0,0,0);\n  --tw-ring-shadow: 0 0 rgba(0,0,0,0);\n  --tw-shadow: 0 0 rgba(0,0,0,0);\n  --tw-shadow-colored: 0 0 rgba(0,0,0,0);\n  --tw-blur:  ;\n  --tw-brightness:  ;\n  --tw-contrast:  ;\n  --tw-grayscale:  ;\n  --tw-hue-rotate:  ;\n  --tw-invert:  ;\n  --tw-saturate:  ;\n  --tw-sepia:  ;\n  --tw-drop-shadow:  ;\n  --tw-backdrop-blur:  ;\n  --tw-backdrop-brightness:  ;\n  --tw-backdrop-contrast:  ;\n  --tw-backdrop-grayscale:  ;\n  --tw-backdrop-hue-rotate:  ;\n  --tw-backdrop-invert:  ;\n  --tw-backdrop-opacity:  ;\n  --tw-backdrop-saturate:  ;\n  --tw-backdrop-sepia:  ;\n}\n\n::backdrop {\n  --tw-border-spacing-x: 0;\n  --tw-border-spacing-y: 0;\n  --tw-translate-x: 0;\n  --tw-translate-y: 0;\n  --tw-rotate: 0;\n  --tw-skew-x: 0;\n  --tw-skew-y: 0;\n  --tw-scale-x: 1;\n  --tw-scale-y: 1;\n  --tw-pan-x:  ;\n  --tw-pan-y:  ;\n  --tw-pinch-zoom:  ;\n  --tw-scroll-snap-strictness: proximity;\n  --tw-ordinal:  ;\n  --tw-slashed-zero:  ;\n  --tw-numeric-figure:  ;\n  --tw-numeric-spacing:  ;\n  --tw-numeric-fraction:  ;\n  --tw-ring-inset:  ;\n  --tw-ring-offset-width: 0px;\n  --tw-ring-offset-color: #fff;\n  --tw-ring-color: rgba(59, 130, 246, 0.5);\n  --tw-ring-offset-shadow: 0 0 rgba(0,0,0,0);\n  --tw-ring-shadow: 0 0 rgba(0,0,0,0);\n  --tw-shadow: 0 0 rgba(0,0,0,0);\n  --tw-shadow-colored: 0 0 rgba(0,0,0,0);\n  --tw-blur:  ;\n  --tw-brightness:  ;\n  --tw-contrast:  ;\n  --tw-grayscale:  ;\n  --tw-hue-rotate:  ;\n  --tw-invert:  ;\n  --tw-saturate:  ;\n  --tw-sepia:  ;\n  --tw-drop-shadow:  ;\n  --tw-backdrop-blur:  ;\n  --tw-backdrop-brightness:  ;\n  --tw-backdrop-contrast:  ;\n  --tw-backdrop-grayscale:  ;\n  --tw-backdrop-hue-rotate:  ;\n  --tw-backdrop-invert:  ;\n  --tw-backdrop-opacity:  ;\n  --tw-backdrop-saturate:  ;\n  --tw-backdrop-sepia:  ;\n}\n\n.sr-only {\n  position: absolute;\n  width: 1px;\n  height: 1px;\n  padding: 0;\n  margin: -1px;\n  overflow: hidden;\n  clip: rect(0, 0, 0, 0);\n  white-space: nowrap;\n  border-width: 0;\n}\n\n.absolute {\n  position: absolute;\n}\n\n.relative {\n  position: relative;\n}\n\n.col-span-6 {\n  grid-column: span 6 / span 6;\n}\n\n.m-2 {\n  margin: 0.5rem;\n}\n\n.mx-auto {\n  margin-left: auto;\n  margin-right: auto;\n}\n\n.my-auto {\n  margin-top: auto;\n  margin-bottom: auto;\n}\n\n.mx-4 {\n  margin-left: 1rem;\n  margin-right: 1rem;\n}\n\n.my-8 {\n  margin-top: 2rem;\n  margin-bottom: 2rem;\n}\n\n.my-3 {\n  margin-top: 0.75rem;\n  margin-bottom: 0.75rem;\n}\n\n.my-2 {\n  margin-top: 0.5rem;\n  margin-bottom: 0.5rem;\n}\n\n.mt-2 {\n  margin-top: 0.5rem;\n}\n\n.mb-2 {\n  margin-bottom: 0.5rem;\n}\n\n.mt-1 {\n  margin-top: 0.25rem;\n}\n\n.mb-1 {\n  margin-bottom: 0.25rem;\n}\n\n.mb-6 {\n  margin-bottom: 1.5rem;\n}\n\n.mt-auto {\n  margin-top: auto;\n}\n\n.mb-5 {\n  margin-bottom: 1.25rem;\n}\n\n.mr-auto {\n  margin-right: auto;\n}\n\n.mr-2 {\n  margin-right: 0.5rem;\n}\n\n.ml-2 {\n  margin-left: 0.5rem;\n}\n\n.ml-4 {\n  margin-left: 1rem;\n}\n\n.mr-4 {\n  margin-right: 1rem;\n}\n\n.mb-0 {\n  margin-bottom: 0px;\n}\n\n.mb-4 {\n  margin-bottom: 1rem;\n}\n\n.ml-auto {\n  margin-left: auto;\n}\n\n.mt-\\[6px\\] {\n  margin-top: 6px;\n}\n\n.mt-\\[5px\\] {\n  margin-top: 5px;\n}\n\n.mb-3 {\n  margin-bottom: 0.75rem;\n}\n\n.mt-3 {\n  margin-top: 0.75rem;\n}\n\n.mt-5 {\n  margin-top: 1.25rem;\n}\n\n.block {\n  display: block;\n}\n\n.flex {\n  display: flex;\n}\n\n.inline-flex {\n  display: inline-flex;\n}\n\n.table {\n  display: table;\n}\n\n.grid {\n  display: grid;\n}\n\n.hidden {\n  display: none;\n}\n\n.h-screen {\n  height: 100vh;\n}\n\n.w-screen {\n  width: 100vw;\n}\n\n.w-full {\n  width: 100%;\n}\n\n.w-auto {\n  width: auto;\n}\n\n.w-16 {\n  width: 4rem;\n}\n\n.max-w-sm {\n  max-width: 24rem;\n}\n\n.border-collapse {\n  border-collapse: collapse;\n}\n\n.grid-cols-2 {\n  grid-template-columns: repeat(2, minmax(0, 1fr));\n}\n\n.flex-row {\n  flex-direction: row;\n}\n\n.flex-col {\n  flex-direction: column;\n}\n\n.content-center {\n  align-content: center;\n}\n\n.items-center {\n  align-items: center;\n}\n\n.justify-center {\n  justify-content: center;\n}\n\n.space-y-0 > :not([hidden]) ~ :not([hidden]) {\n  --tw-space-y-reverse: 0;\n  margin-top: calc(0px * (1 - var(--tw-space-y-reverse)));\n  margin-top: calc(0px * calc(1 - var(--tw-space-y-reverse)));\n  margin-bottom: calc(0px * var(--tw-space-y-reverse));\n}\n\n.overflow-hidden {\n  overflow: hidden;\n}\n\n.overflow-x-auto {\n  overflow-x: auto;\n}\n\n.rounded-lg {\n  border-radius: 0.5rem;\n}\n\n.rounded-none {\n  border-radius: 0px;\n}\n\n.rounded-b-md {\n  border-bottom-right-radius: 0.375rem;\n  border-bottom-left-radius: 0.375rem;\n}\n\n.border {\n  border-width: 1px;\n}\n\n.border-b {\n  border-bottom-width: 1px;\n}\n\n.border-transparent {\n  border-color: transparent;\n}\n\n.border-neutral-100 {\n  --tw-border-opacity: 1;\n  border-color: rgba(245, 245, 245, var(--tw-border-opacity));\n}\n\n.border-neutral-200 {\n  --tw-border-opacity: 1;\n  border-color: rgba(229, 229, 229, var(--tw-border-opacity));\n}\n\n.border-white {\n  --tw-border-opacity: 1;\n  border-color: rgba(255, 255, 255, var(--tw-border-opacity));\n}\n\n.border-gray-300 {\n  --tw-border-opacity: 1;\n  border-color: rgba(209, 213, 219, var(--tw-border-opacity));\n}\n\n.bg-white {\n  --tw-bg-opacity: 1;\n  background-color: rgba(255, 255, 255, var(--tw-bg-opacity));\n}\n\n.bg-blue-500 {\n  --tw-bg-opacity: 1;\n  background-color: rgba(59, 130, 246, var(--tw-bg-opacity));\n}\n\n.bg-gray-50 {\n  --tw-bg-opacity: 1;\n  background-color: rgba(249, 250, 251, var(--tw-bg-opacity));\n}\n\n.bg-blue-600 {\n  --tw-bg-opacity: 1;\n  background-color: rgba(37, 99, 235, var(--tw-bg-opacity));\n}\n\n.bg-neutral-100 {\n  --tw-bg-opacity: 1;\n  background-color: rgba(245, 245, 245, var(--tw-bg-opacity));\n}\n\n.bg-gradient-to-br {\n  background-image: linear-gradient(to bottom right, var(--tw-gradient-stops));\n}\n\n.from-pink-500 {\n  --tw-gradient-from: #ec4899;\n  --tw-gradient-to: rgba(236, 72, 153, 0);\n  --tw-gradient-stops: var(--tw-gradient-from), var(--tw-gradient-to);\n}\n\n.from-violet-500 {\n  --tw-gradient-from: #8b5cf6;\n  --tw-gradient-to: rgba(139, 92, 246, 0);\n  --tw-gradient-stops: var(--tw-gradient-from), var(--tw-gradient-to);\n}\n\n.from-neutral-600 {\n  --tw-gradient-from: #525252;\n  --tw-gradient-to: rgba(82, 82, 82, 0);\n  --tw-gradient-stops: var(--tw-gradient-from), var(--tw-gradient-to);\n}\n\n.from-green-500 {\n  --tw-gradient-from: #22c55e;\n  --tw-gradient-to: rgba(34, 197, 94, 0);\n  --tw-gradient-stops: var(--tw-gradient-from), var(--tw-gradient-to);\n}\n\n.from-blue-500 {\n  --tw-gradient-from: #3b82f6;\n  --tw-gradient-to: rgba(59, 130, 246, 0);\n  --tw-gradient-stops: var(--tw-gradient-from), var(--tw-gradient-to);\n}\n\n.from-red-500 {\n  --tw-gradient-from: #ef4444;\n  --tw-gradient-to: rgba(239, 68, 68, 0);\n  --tw-gradient-stops: var(--tw-gradient-from), var(--tw-gradient-to);\n}\n\n.to-pink-300 {\n  --tw-gradient-to: #f9a8d4;\n}\n\n.to-violet-300 {\n  --tw-gradient-to: #c4b5fd;\n}\n\n.to-neutral-400 {\n  --tw-gradient-to: #a3a3a3;\n}\n\n.to-green-300 {\n  --tw-gradient-to: #86efac;\n}\n\n.to-blue-300 {\n  --tw-gradient-to: #93c5fd;\n}\n\n.to-red-300 {\n  --tw-gradient-to: #fca5a5;\n}\n\n.p-2 {\n  padding: 0.5rem;\n}\n\n.px-6 {\n  padding-left: 1.5rem;\n  padding-right: 1.5rem;\n}\n\n.py-4 {\n  padding-top: 1rem;\n  padding-bottom: 1rem;\n}\n\n.px-4 {\n  padding-left: 1rem;\n  padding-right: 1rem;\n}\n\n.py-5 {\n  padding-top: 1.25rem;\n  padding-bottom: 1.25rem;\n}\n\n.py-2 {\n  padding-top: 0.5rem;\n  padding-bottom: 0.5rem;\n}\n\n.py-20 {\n  padding-top: 5rem;\n  padding-bottom: 5rem;\n}\n\n.py-\\[6px\\] {\n  padding-top: 6px;\n  padding-bottom: 6px;\n}\n\n.px-0 {\n  padding-left: 0px;\n  padding-right: 0px;\n}\n\n.px-3 {\n  padding-left: 0.75rem;\n  padding-right: 0.75rem;\n}\n\n.py-1 {\n  padding-top: 0.25rem;\n  padding-bottom: 0.25rem;\n}\n\n.py-\\[8px\\] {\n  padding-top: 8px;\n  padding-bottom: 8px;\n}\n\n.px-8 {\n  padding-left: 2rem;\n  padding-right: 2rem;\n}\n\n.py-\\[2px\\] {\n  padding-top: 2px;\n  padding-bottom: 2px;\n}\n\n.px-5 {\n  padding-left: 1.25rem;\n  padding-right: 1.25rem;\n}\n\n.pr-3 {\n  padding-right: 0.75rem;\n}\n\n.pr-4 {\n  padding-right: 1rem;\n}\n\n.text-right {\n  text-align: right;\n}\n\n.text-2xl {\n  font-size: 1.5rem;\n  line-height: 2rem;\n}\n\n.text-sm {\n  font-size: 0.875rem;\n  line-height: 1.25rem;\n}\n\n.text-lg {\n  font-size: 1.125rem;\n  line-height: 1.75rem;\n}\n\n.font-semibold {\n  font-weight: 600;\n}\n\n.font-medium {\n  font-weight: 500;\n}\n\n.font-bold {\n  font-weight: 700;\n}\n\n.leading-6 {\n  line-height: 1.5rem;\n}\n\n.text-white {\n  --tw-text-opacity: 1;\n  color: rgba(255, 255, 255, var(--tw-text-opacity));\n}\n\n.text-neutral-100 {\n  --tw-text-opacity: 1;\n  color: rgba(245, 245, 245, var(--tw-text-opacity));\n}\n\n.text-neutral-600 {\n  --tw-text-opacity: 1;\n  color: rgba(82, 82, 82, var(--tw-text-opacity));\n}\n\n.text-blue-500 {\n  --tw-text-opacity: 1;\n  color: rgba(59, 130, 246, var(--tw-text-opacity));\n}\n\n.text-gray-900 {\n  --tw-text-opacity: 1;\n  color: rgba(17, 24, 39, var(--tw-text-opacity));\n}\n\n.text-gray-700 {\n  --tw-text-opacity: 1;\n  color: rgba(55, 65, 81, var(--tw-text-opacity));\n}\n\n.text-gray-500 {\n  --tw-text-opacity: 1;\n  color: rgba(107, 114, 128, var(--tw-text-opacity));\n}\n\n.shadow-sm {\n  --tw-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.05);\n  --tw-shadow-colored: 0 1px 2px 0 var(--tw-shadow-color);\n  box-shadow: 0 0 rgba(0,0,0,0), 0 0 rgba(0,0,0,0), var(--tw-shadow);\n  box-shadow: 0 0 rgba(0,0,0,0), 0 0 rgba(0,0,0,0), var(--tw-shadow);\n  box-shadow: var(--tw-ring-offset-shadow, 0 0 rgba(0,0,0,0)), var(--tw-ring-shadow, 0 0 rgba(0,0,0,0)), var(--tw-shadow);\n}\n\n.shadow-lg {\n  --tw-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -4px rgba(0, 0, 0, 0.1);\n  --tw-shadow-colored: 0 10px 15px -3px var(--tw-shadow-color), 0 4px 6px -4px var(--tw-shadow-color);\n  box-shadow: 0 0 rgba(0,0,0,0), 0 0 rgba(0,0,0,0), var(--tw-shadow);\n  box-shadow: 0 0 rgba(0,0,0,0), 0 0 rgba(0,0,0,0), var(--tw-shadow);\n  box-shadow: var(--tw-ring-offset-shadow, 0 0 rgba(0,0,0,0)), var(--tw-ring-shadow, 0 0 rgba(0,0,0,0)), var(--tw-shadow);\n}\n\n.shadow {\n  --tw-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1), 0 1px 2px -1px rgba(0, 0, 0, 0.1);\n  --tw-shadow-colored: 0 1px 3px 0 var(--tw-shadow-color), 0 1px 2px -1px var(--tw-shadow-color);\n  box-shadow: 0 0 rgba(0,0,0,0), 0 0 rgba(0,0,0,0), var(--tw-shadow);\n  box-shadow: 0 0 rgba(0,0,0,0), 0 0 rgba(0,0,0,0), var(--tw-shadow);\n  box-shadow: var(--tw-ring-offset-shadow, 0 0 rgba(0,0,0,0)), var(--tw-ring-shadow, 0 0 rgba(0,0,0,0)), var(--tw-shadow);\n}\n\n.outline-none {\n  outline: 2px solid transparent;\n  outline-offset: 2px;\n}\n\n.font-jost {\n  font-family: \"Jost\";\n}\n\n.font-inter {\n  font-family: \"Inter\";\n}\n\n.code {\n  font-family: \"Source Code Pro\", monospace;\n  display: block;\n  background-color: white;\n  color: #000000;\n  padding: 1em;\n  word-wrap: break-word;\n  white-space: pre-wrap;\n}\n\n.sidenav {\n  height: 100%;\n  /* 100% Full-height */\n  width: 0;\n  /* 0 width - change this with JavaScript */\n  position: fixed;\n  /* Stay in place */\n  z-index: 1;\n  /* Stay on top */\n  top: 0;\n  /* Stay at the top */\n  left: 0;\n  overflow-x: hidden;\n  /* Disable horizontal scroll */\n  padding-top: 60px;\n  /* Place content 60px from the top */\n  transition: 0.5s;\n  /* 0.5 second transition effect to slide in the sidenav */\n}\n\n/* The navigation menu links */\n\n.sidenav a {\n  display: block;\n}\n\nselect {\n  -webkit-appearance: none;\n     -moz-appearance: none;\n          appearance: none;\n  background-color: #fff;\n  border-color: #6b7280;\n  border-width: 1px;\n  border-radius: 0px;\n  padding-top: 0.5rem;\n  padding-right: 0.75rem;\n  padding-bottom: 0.5rem;\n  padding-left: 0.75rem;\n  font-size: 1rem;\n  line-height: 1.5rem;\n  --tw-shadow: 0 0 rgba(0,0,0,0);\n}\n\n select:focus {\n  outline: 2px solid transparent;\n  outline-offset: 2px;\n  --tw-ring-inset: var(--tw-empty,/*!*/ /*!*/);\n  --tw-ring-offset-width: 0px;\n  --tw-ring-offset-color: #fff;\n  --tw-ring-color: #2563eb;\n  --tw-ring-offset-shadow: var(--tw-ring-inset) 0 0 0 var(--tw-ring-offset-width) var(--tw-ring-offset-color);\n  --tw-ring-shadow: var(--tw-ring-inset) 0 0 0 calc(1px + var(--tw-ring-offset-width)) var(--tw-ring-color);\n  box-shadow: var(--tw-ring-offset-shadow), var(--tw-ring-shadow), var(--tw-shadow);\n  border-color: #2563eb;\n}\n\nselect {\n  background-image: url(" +
            g +
            ");\n  background-position: right 0.5rem center;\n  background-size: 1.5em 1.5em;\n  -webkit-print-color-adjust: exact;\n     color-adjust: exact;\n          print-color-adjust: exact;\n  margin: 0px;\n  margin-top: 0.5rem;\n  display: block;\n  width: 100%;\n  -webkit-appearance: none;\n     -moz-appearance: none;\n          appearance: none;\n  border-radius: 0.25rem;\n  border-width: 1px;\n  border-style: solid;\n  --tw-border-opacity: 1;\n  border-color: rgba(209, 213, 219, var(--tw-border-opacity));\n  --tw-bg-opacity: 1;\n  background-color: rgba(255, 255, 255, var(--tw-bg-opacity));\n  background-clip: padding-box;\n  background-repeat: no-repeat;\n  padding-left: 0.75rem;\n  padding-right: 0.75rem;\n  padding-top: 0.375rem;\n  padding-bottom: 0.375rem;\n  font-size: 1rem;\n  line-height: 1.5rem;\n  font-weight: 400;\n  --tw-text-opacity: 1;\n  color: rgba(55, 65, 81, var(--tw-text-opacity));\n  transition-property: color, background-color, border-color, fill, stroke, opacity, box-shadow, transform, filter, -webkit-text-decoration-color, -webkit-backdrop-filter;\n  transition-property: color, background-color, border-color, text-decoration-color, fill, stroke, opacity, box-shadow, transform, filter, backdrop-filter;\n  transition-property: color, background-color, border-color, text-decoration-color, fill, stroke, opacity, box-shadow, transform, filter, backdrop-filter, -webkit-text-decoration-color, -webkit-backdrop-filter;\n  transition-duration: 150ms;\n  transition-timing-function: cubic-bezier(0.4, 0, 0.2, 1);\n}\n\nselect:focus {\n  --tw-border-opacity: 1;\n  border-color: rgba(37, 99, 235, var(--tw-border-opacity));\n  --tw-bg-opacity: 1;\n  background-color: rgba(255, 255, 255, var(--tw-bg-opacity));\n  --tw-text-opacity: 1;\n  color: rgba(55, 65, 81, var(--tw-text-opacity));\n  outline: 2px solid transparent;\n  outline-offset: 2px;\n}\n\n/* Position and style the close button (top right corner) */\n\n.sidenav .closebtn {\n  position: absolute;\n  top: 0;\n  right: 25px;\n  font-size: 28px;\n  margin-left: 50px;\n}\n\n@media screen and (max-height: 450px) {\n  .sidenav {\n    padding-top: 15px;\n  }\n\n  .sidenav a {\n    font-size: 18px;\n  }\n}\n\n.file\\:mr-4::-webkit-file-upload-button {\n  margin-right: 1rem;\n}\n\n.file\\:mr-4::file-selector-button {\n  margin-right: 1rem;\n}\n\n.file\\:rounded-full::-webkit-file-upload-button {\n  border-radius: 9999px;\n}\n\n.file\\:rounded-full::file-selector-button {\n  border-radius: 9999px;\n}\n\n.file\\:border-0::-webkit-file-upload-button {\n  border-width: 0px;\n}\n\n.file\\:border-0::file-selector-button {\n  border-width: 0px;\n}\n\n.file\\:bg-blue-50::-webkit-file-upload-button {\n  --tw-bg-opacity: 1;\n  background-color: rgba(239, 246, 255, var(--tw-bg-opacity));\n}\n\n.file\\:bg-blue-50::file-selector-button {\n  --tw-bg-opacity: 1;\n  background-color: rgba(239, 246, 255, var(--tw-bg-opacity));\n}\n\n.file\\:py-2::-webkit-file-upload-button {\n  padding-top: 0.5rem;\n  padding-bottom: 0.5rem;\n}\n\n.file\\:py-2::file-selector-button {\n  padding-top: 0.5rem;\n  padding-bottom: 0.5rem;\n}\n\n.file\\:px-4::-webkit-file-upload-button {\n  padding-left: 1rem;\n  padding-right: 1rem;\n}\n\n.file\\:px-4::file-selector-button {\n  padding-left: 1rem;\n  padding-right: 1rem;\n}\n\n.file\\:text-sm::-webkit-file-upload-button {\n  font-size: 0.875rem;\n  line-height: 1.25rem;\n}\n\n.file\\:text-sm::file-selector-button {\n  font-size: 0.875rem;\n  line-height: 1.25rem;\n}\n\n.file\\:font-semibold::-webkit-file-upload-button {\n  font-weight: 600;\n}\n\n.file\\:font-semibold::file-selector-button {\n  font-weight: 600;\n}\n\n.file\\:text-blue-700::-webkit-file-upload-button {\n  --tw-text-opacity: 1;\n  color: rgba(29, 78, 216, var(--tw-text-opacity));\n}\n\n.file\\:text-blue-700::file-selector-button {\n  --tw-text-opacity: 1;\n  color: rgba(29, 78, 216, var(--tw-text-opacity));\n}\n\n.hover\\:bg-blue-700:hover {\n  --tw-bg-opacity: 1;\n  background-color: rgba(29, 78, 216, var(--tw-bg-opacity));\n}\n\n.hover\\:bg-blue-400:hover {\n  --tw-bg-opacity: 1;\n  background-color: rgba(96, 165, 250, var(--tw-bg-opacity));\n}\n\n.hover\\:file\\:bg-blue-100::-webkit-file-upload-button:hover {\n  --tw-bg-opacity: 1;\n  background-color: rgba(219, 234, 254, var(--tw-bg-opacity));\n}\n\n.hover\\:file\\:bg-blue-100::file-selector-button:hover {\n  --tw-bg-opacity: 1;\n  background-color: rgba(219, 234, 254, var(--tw-bg-opacity));\n}\n\n.focus\\:border-blue-500:focus {\n  --tw-border-opacity: 1;\n  border-color: rgba(59, 130, 246, var(--tw-border-opacity));\n}\n\n.focus\\:border-indigo-500:focus {\n  --tw-border-opacity: 1;\n  border-color: rgba(99, 102, 241, var(--tw-border-opacity));\n}\n\n.focus\\:outline-none:focus {\n  outline: 2px solid transparent;\n  outline-offset: 2px;\n}\n\n.focus\\:ring-2:focus {\n  --tw-ring-offset-shadow: var(--tw-ring-inset) 0 0 0 var(--tw-ring-offset-width) var(--tw-ring-offset-color);\n  --tw-ring-shadow: var(--tw-ring-inset) 0 0 0 calc(2px + var(--tw-ring-offset-width)) var(--tw-ring-color);\n  box-shadow: var(--tw-ring-offset-shadow), var(--tw-ring-shadow), 0 0 rgba(0,0,0,0);\n  box-shadow: var(--tw-ring-offset-shadow), var(--tw-ring-shadow), 0 0 rgba(0,0,0,0);\n  box-shadow: var(--tw-ring-offset-shadow), var(--tw-ring-shadow), var(--tw-shadow, 0 0 rgba(0,0,0,0));\n}\n\n.focus\\:ring-indigo-500:focus {\n  --tw-ring-opacity: 1;\n  --tw-ring-color: rgba(99, 102, 241, var(--tw-ring-opacity));\n}\n\n.focus\\:ring-blue-500:focus {\n  --tw-ring-opacity: 1;\n  --tw-ring-color: rgba(59, 130, 246, var(--tw-ring-opacity));\n}\n\n.focus\\:ring-offset-2:focus {\n  --tw-ring-offset-width: 2px;\n}\n\n@media (min-width: 640px) {\n  .sm\\:col-span-3 {\n    grid-column: span 3 / span 3;\n  }\n\n  .sm\\:p-6 {\n    padding: 1.5rem;\n  }\n\n  .sm\\:px-6 {\n    padding-left: 1.5rem;\n    padding-right: 1.5rem;\n  }\n\n  .sm\\:py-0 {\n    padding-top: 0px;\n    padding-bottom: 0px;\n  }\n\n  .sm\\:px-4 {\n    padding-left: 1rem;\n    padding-right: 1rem;\n  }\n\n  .sm\\:pt-2 {\n    padding-top: 0.5rem;\n  }\n\n  .sm\\:pr-4 {\n    padding-right: 1rem;\n  }\n\n  .sm\\:text-sm {\n    font-size: 0.875rem;\n    line-height: 1.25rem;\n  }\n\n  .sm\\:font-semibold {\n    font-weight: 600;\n  }\n}\n\n@media (min-width: 768px) {\n  .md\\:mr-0 {\n    margin-right: 0px;\n  }\n\n  .md\\:mb-2 {\n    margin-bottom: 0.5rem;\n  }\n\n  .md\\:ml-0 {\n    margin-left: 0px;\n  }\n\n  .md\\:inline-flex {\n    display: inline-flex;\n  }\n\n  .md\\:grid-cols-3 {\n    grid-template-columns: repeat(3, minmax(0, 1fr));\n  }\n\n  .md\\:flex-col {\n    flex-direction: column;\n  }\n\n  .md\\:items-center {\n    align-items: center;\n  }\n\n  .md\\:space-y-4 > :not([hidden]) ~ :not([hidden]) {\n    --tw-space-y-reverse: 0;\n    margin-top: calc(1rem * (1 - var(--tw-space-y-reverse)));\n    margin-top: calc(1rem * calc(1 - var(--tw-space-y-reverse)));\n    margin-bottom: calc(1rem * var(--tw-space-y-reverse));\n  }\n\n  .md\\:py-\\[6px\\] {\n    padding-top: 6px;\n    padding-bottom: 6px;\n  }\n\n  .md\\:py-8 {\n    padding-top: 2rem;\n    padding-bottom: 2rem;\n  }\n\n  .md\\:text-left {\n    text-align: left;\n  }\n\n  .md\\:text-lg {\n    font-size: 1.125rem;\n    line-height: 1.75rem;\n  }\n\n  .md\\:text-5xl {\n    font-size: 3rem;\n    line-height: 1;\n  }\n}\n\n@media (min-width: 1024px) {\n  .lg\\:mx-auto {\n    margin-left: auto;\n    margin-right: auto;\n  }\n\n  .lg\\:my-auto {\n    margin-top: auto;\n    margin-bottom: auto;\n  }\n\n  .lg\\:my-5 {\n    margin-top: 1.25rem;\n    margin-bottom: 1.25rem;\n  }\n\n  .lg\\:mb-0 {\n    margin-bottom: 0px;\n  }\n\n  .lg\\:mt-2 {\n    margin-top: 0.5rem;\n  }\n\n  .lg\\:mb-5 {\n    margin-bottom: 1.25rem;\n  }\n\n  .lg\\:mb-2 {\n    margin-bottom: 0.5rem;\n  }\n\n  .lg\\:w-1\\/3 {\n    width: 33.333333%;\n  }\n\n  .lg\\:w-1\\/2 {\n    width: 50%;\n  }\n\n  .lg\\:rounded-t-md {\n    border-top-left-radius: 0.375rem;\n    border-top-right-radius: 0.375rem;\n  }\n\n  .lg\\:py-20 {\n    padding-top: 5rem;\n    padding-bottom: 5rem;\n  }\n\n  .lg\\:py-1 {\n    padding-top: 0.25rem;\n    padding-bottom: 0.25rem;\n  }\n\n  .lg\\:px-6 {\n    padding-left: 1.5rem;\n    padding-right: 1.5rem;\n  }\n\n  .lg\\:px-0 {\n    padding-left: 0px;\n    padding-right: 0px;\n  }\n\n  .lg\\:text-lg {\n    font-size: 1.125rem;\n    line-height: 1.75rem;\n  }\n}\n",
          "",
          {
            version: 3,
            sources: ["webpack://./src/styles.css"],
            names: [],
            mappings:
              "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",
            sourcesContent: [
              "/*\n! tailwindcss v3.1.8 | MIT License | https://tailwindcss.com\n*/\n\n/*\n1. Prevent padding and border from affecting element width. (https://github.com/mozdevs/cssremedy/issues/4)\n2. Allow adding a border to an element by just adding a border-width. (https://github.com/tailwindcss/tailwindcss/pull/116)\n*/\n\n*,\n::before,\n::after {\n  box-sizing: border-box;\n  /* 1 */\n  border-width: 0;\n  /* 2 */\n  border-style: solid;\n  /* 2 */\n  border-color: #e5e7eb;\n  /* 2 */\n}\n\n::before,\n::after {\n  --tw-content: '';\n}\n\n/*\n1. Use a consistent sensible line-height in all browsers.\n2. Prevent adjustments of font size after orientation changes in iOS.\n3. Use a more readable tab size.\n4. Use the user's configured `sans` font-family by default.\n*/\n\nhtml {\n  line-height: 1.5;\n  /* 1 */\n  -webkit-text-size-adjust: 100%;\n  /* 2 */\n  -moz-tab-size: 4;\n  /* 3 */\n  -o-tab-size: 4;\n     tab-size: 4;\n  /* 3 */\n  font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, \"Noto Sans\", sans-serif, \"Apple Color Emoji\", \"Segoe UI Emoji\", \"Segoe UI Symbol\", \"Noto Color Emoji\";\n  /* 4 */\n}\n\n/*\n1. Remove the margin in all browsers.\n2. Inherit line-height from `html` so users can set them as a class directly on the `html` element.\n*/\n\nbody {\n  margin: 0;\n  /* 1 */\n  line-height: inherit;\n  /* 2 */\n}\n\n/*\n1. Add the correct height in Firefox.\n2. Correct the inheritance of border color in Firefox. (https://bugzilla.mozilla.org/show_bug.cgi?id=190655)\n3. Ensure horizontal rules are visible by default.\n*/\n\nhr {\n  height: 0;\n  /* 1 */\n  color: inherit;\n  /* 2 */\n  border-top-width: 1px;\n  /* 3 */\n}\n\n/*\nAdd the correct text decoration in Chrome, Edge, and Safari.\n*/\n\nabbr:where([title]) {\n  -webkit-text-decoration: underline dotted;\n          text-decoration: underline dotted;\n}\n\n/*\nRemove the default font size and weight for headings.\n*/\n\nh1,\nh2,\nh3,\nh4,\nh5,\nh6 {\n  font-size: inherit;\n  font-weight: inherit;\n}\n\n/*\nReset links to optimize for opt-in styling instead of opt-out.\n*/\n\na {\n  color: inherit;\n  text-decoration: inherit;\n}\n\n/*\nAdd the correct font weight in Edge and Safari.\n*/\n\nb,\nstrong {\n  font-weight: bolder;\n}\n\n/*\n1. Use the user's configured `mono` font family by default.\n2. Correct the odd `em` font sizing in all browsers.\n*/\n\ncode,\nkbd,\nsamp,\npre {\n  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, \"Liberation Mono\", \"Courier New\", monospace;\n  /* 1 */\n  font-size: 1em;\n  /* 2 */\n}\n\n/*\nAdd the correct font size in all browsers.\n*/\n\nsmall {\n  font-size: 80%;\n}\n\n/*\nPrevent `sub` and `sup` elements from affecting the line height in all browsers.\n*/\n\nsub,\nsup {\n  font-size: 75%;\n  line-height: 0;\n  position: relative;\n  vertical-align: baseline;\n}\n\nsub {\n  bottom: -0.25em;\n}\n\nsup {\n  top: -0.5em;\n}\n\n/*\n1. Remove text indentation from table contents in Chrome and Safari. (https://bugs.chromium.org/p/chromium/issues/detail?id=999088, https://bugs.webkit.org/show_bug.cgi?id=201297)\n2. Correct table border color inheritance in all Chrome and Safari. (https://bugs.chromium.org/p/chromium/issues/detail?id=935729, https://bugs.webkit.org/show_bug.cgi?id=195016)\n3. Remove gaps between table borders by default.\n*/\n\ntable {\n  text-indent: 0;\n  /* 1 */\n  border-color: inherit;\n  /* 2 */\n  border-collapse: collapse;\n  /* 3 */\n}\n\n/*\n1. Change the font styles in all browsers.\n2. Remove the margin in Firefox and Safari.\n3. Remove default padding in all browsers.\n*/\n\nbutton,\ninput,\noptgroup,\nselect,\ntextarea {\n  font-family: inherit;\n  /* 1 */\n  font-size: 100%;\n  /* 1 */\n  font-weight: inherit;\n  /* 1 */\n  line-height: inherit;\n  /* 1 */\n  color: inherit;\n  /* 1 */\n  margin: 0;\n  /* 2 */\n  padding: 0;\n  /* 3 */\n}\n\n/*\nRemove the inheritance of text transform in Edge and Firefox.\n*/\n\nbutton,\nselect {\n  text-transform: none;\n}\n\n/*\n1. Correct the inability to style clickable types in iOS and Safari.\n2. Remove default button styles.\n*/\n\nbutton,\n[type='button'],\n[type='reset'],\n[type='submit'] {\n  -webkit-appearance: button;\n  /* 1 */\n  background-color: transparent;\n  /* 2 */\n  background-image: none;\n  /* 2 */\n}\n\n/*\nUse the modern Firefox focus style for all focusable elements.\n*/\n\n:-moz-focusring {\n  outline: auto;\n}\n\n/*\nRemove the additional `:invalid` styles in Firefox. (https://github.com/mozilla/gecko-dev/blob/2f9eacd9d3d995c937b4251a5557d95d494c9be1/layout/style/res/forms.css#L728-L737)\n*/\n\n:-moz-ui-invalid {\n  box-shadow: none;\n}\n\n/*\nAdd the correct vertical alignment in Chrome and Firefox.\n*/\n\nprogress {\n  vertical-align: baseline;\n}\n\n/*\nCorrect the cursor style of increment and decrement buttons in Safari.\n*/\n\n::-webkit-inner-spin-button,\n::-webkit-outer-spin-button {\n  height: auto;\n}\n\n/*\n1. Correct the odd appearance in Chrome and Safari.\n2. Correct the outline style in Safari.\n*/\n\n[type='search'] {\n  -webkit-appearance: textfield;\n  /* 1 */\n  outline-offset: -2px;\n  /* 2 */\n}\n\n/*\nRemove the inner padding in Chrome and Safari on macOS.\n*/\n\n::-webkit-search-decoration {\n  -webkit-appearance: none;\n}\n\n/*\n1. Correct the inability to style clickable types in iOS and Safari.\n2. Change font properties to `inherit` in Safari.\n*/\n\n::-webkit-file-upload-button {\n  -webkit-appearance: button;\n  /* 1 */\n  font: inherit;\n  /* 2 */\n}\n\n/*\nAdd the correct display in Chrome and Safari.\n*/\n\nsummary {\n  display: list-item;\n}\n\n/*\nRemoves the default spacing and border for appropriate elements.\n*/\n\nblockquote,\ndl,\ndd,\nh1,\nh2,\nh3,\nh4,\nh5,\nh6,\nhr,\nfigure,\np,\npre {\n  margin: 0;\n}\n\nfieldset {\n  margin: 0;\n  padding: 0;\n}\n\nlegend {\n  padding: 0;\n}\n\nol,\nul,\nmenu {\n  list-style: none;\n  margin: 0;\n  padding: 0;\n}\n\n/*\nPrevent resizing textareas horizontally by default.\n*/\n\ntextarea {\n  resize: vertical;\n}\n\n/*\n1. Reset the default placeholder opacity in Firefox. (https://github.com/tailwindlabs/tailwindcss/issues/3300)\n2. Set the default placeholder color to the user's configured gray 400 color.\n*/\n\ninput::-moz-placeholder, textarea::-moz-placeholder {\n  opacity: 1;\n  /* 1 */\n  color: #9ca3af;\n  /* 2 */\n}\n\ninput::placeholder,\ntextarea::placeholder {\n  opacity: 1;\n  /* 1 */\n  color: #9ca3af;\n  /* 2 */\n}\n\n/*\nSet the default cursor for buttons.\n*/\n\nbutton,\n[role=\"button\"] {\n  cursor: pointer;\n}\n\n/*\nMake sure disabled buttons don't get the pointer cursor.\n*/\n\n:disabled {\n  cursor: default;\n}\n\n/*\n1. Make replaced elements `display: block` by default. (https://github.com/mozdevs/cssremedy/issues/14)\n2. Add `vertical-align: middle` to align replaced elements more sensibly by default. (https://github.com/jensimmons/cssremedy/issues/14#issuecomment-634934210)\n   This can trigger a poorly considered lint error in some tools but is included by design.\n*/\n\nimg,\nsvg,\nvideo,\ncanvas,\naudio,\niframe,\nembed,\nobject {\n  display: block;\n  /* 1 */\n  vertical-align: middle;\n  /* 2 */\n}\n\n/*\nConstrain images and videos to the parent width and preserve their intrinsic aspect ratio. (https://github.com/mozdevs/cssremedy/issues/14)\n*/\n\nimg,\nvideo {\n  max-width: 100%;\n  height: auto;\n}\n\n[type='text'],[type='email'],[type='url'],[type='password'],[type='number'],[type='date'],[type='datetime-local'],[type='month'],[type='search'],[type='tel'],[type='time'],[type='week'],[multiple],textarea,select {\n  -webkit-appearance: none;\n     -moz-appearance: none;\n          appearance: none;\n  background-color: #fff;\n  border-color: #6b7280;\n  border-width: 1px;\n  border-radius: 0px;\n  padding-top: 0.5rem;\n  padding-right: 0.75rem;\n  padding-bottom: 0.5rem;\n  padding-left: 0.75rem;\n  font-size: 1rem;\n  line-height: 1.5rem;\n  --tw-shadow: 0 0 #0000;\n}\n\n[type='text']:focus, [type='email']:focus, [type='url']:focus, [type='password']:focus, [type='number']:focus, [type='date']:focus, [type='datetime-local']:focus, [type='month']:focus, [type='search']:focus, [type='tel']:focus, [type='time']:focus, [type='week']:focus, [multiple]:focus, textarea:focus, select:focus {\n  outline: 2px solid transparent;\n  outline-offset: 2px;\n  --tw-ring-inset: var(--tw-empty,/*!*/ /*!*/);\n  --tw-ring-offset-width: 0px;\n  --tw-ring-offset-color: #fff;\n  --tw-ring-color: #2563eb;\n  --tw-ring-offset-shadow: var(--tw-ring-inset) 0 0 0 var(--tw-ring-offset-width) var(--tw-ring-offset-color);\n  --tw-ring-shadow: var(--tw-ring-inset) 0 0 0 calc(1px + var(--tw-ring-offset-width)) var(--tw-ring-color);\n  box-shadow: var(--tw-ring-offset-shadow), var(--tw-ring-shadow), var(--tw-shadow);\n  border-color: #2563eb;\n}\n\ninput::-moz-placeholder, textarea::-moz-placeholder {\n  color: #6b7280;\n  opacity: 1;\n}\n\ninput::placeholder,textarea::placeholder {\n  color: #6b7280;\n  opacity: 1;\n}\n\n::-webkit-datetime-edit-fields-wrapper {\n  padding: 0;\n}\n\n::-webkit-date-and-time-value {\n  min-height: 1.5em;\n}\n\n::-webkit-datetime-edit,::-webkit-datetime-edit-year-field,::-webkit-datetime-edit-month-field,::-webkit-datetime-edit-day-field,::-webkit-datetime-edit-hour-field,::-webkit-datetime-edit-minute-field,::-webkit-datetime-edit-second-field,::-webkit-datetime-edit-millisecond-field,::-webkit-datetime-edit-meridiem-field {\n  padding-top: 0;\n  padding-bottom: 0;\n}\n\nselect {\n  background-image: url(\"data:image/svg+xml,%3csvg xmlns='http://www.w3.org/2000/svg' fill='none' viewBox='0 0 20 20'%3e%3cpath stroke='%236b7280' stroke-linecap='round' stroke-linejoin='round' stroke-width='1.5' d='M6 8l4 4 4-4'/%3e%3c/svg%3e\");\n  background-position: right 0.5rem center;\n  background-repeat: no-repeat;\n  background-size: 1.5em 1.5em;\n  padding-right: 2.5rem;\n  -webkit-print-color-adjust: exact;\n     color-adjust: exact;\n          print-color-adjust: exact;\n}\n\n[multiple] {\n  background-image: initial;\n  background-position: initial;\n  background-repeat: unset;\n  background-size: initial;\n  padding-right: 0.75rem;\n  -webkit-print-color-adjust: unset;\n     color-adjust: unset;\n          print-color-adjust: unset;\n}\n\n[type='checkbox'],[type='radio'] {\n  -webkit-appearance: none;\n     -moz-appearance: none;\n          appearance: none;\n  padding: 0;\n  -webkit-print-color-adjust: exact;\n     color-adjust: exact;\n          print-color-adjust: exact;\n  display: inline-block;\n  vertical-align: middle;\n  background-origin: border-box;\n  -webkit-user-select: none;\n     -moz-user-select: none;\n          user-select: none;\n  flex-shrink: 0;\n  height: 1rem;\n  width: 1rem;\n  color: #2563eb;\n  background-color: #fff;\n  border-color: #6b7280;\n  border-width: 1px;\n  --tw-shadow: 0 0 #0000;\n}\n\n[type='checkbox'] {\n  border-radius: 0px;\n}\n\n[type='radio'] {\n  border-radius: 100%;\n}\n\n[type='checkbox']:focus,[type='radio']:focus {\n  outline: 2px solid transparent;\n  outline-offset: 2px;\n  --tw-ring-inset: var(--tw-empty,/*!*/ /*!*/);\n  --tw-ring-offset-width: 2px;\n  --tw-ring-offset-color: #fff;\n  --tw-ring-color: #2563eb;\n  --tw-ring-offset-shadow: var(--tw-ring-inset) 0 0 0 var(--tw-ring-offset-width) var(--tw-ring-offset-color);\n  --tw-ring-shadow: var(--tw-ring-inset) 0 0 0 calc(2px + var(--tw-ring-offset-width)) var(--tw-ring-color);\n  box-shadow: var(--tw-ring-offset-shadow), var(--tw-ring-shadow), var(--tw-shadow);\n}\n\n[type='checkbox']:checked,[type='radio']:checked {\n  border-color: transparent;\n  background-color: currentColor;\n  background-size: 100% 100%;\n  background-position: center;\n  background-repeat: no-repeat;\n}\n\n[type='checkbox']:checked {\n  background-image: url(\"data:image/svg+xml,%3csvg viewBox='0 0 16 16' fill='white' xmlns='http://www.w3.org/2000/svg'%3e%3cpath d='M12.207 4.793a1 1 0 010 1.414l-5 5a1 1 0 01-1.414 0l-2-2a1 1 0 011.414-1.414L6.5 9.086l4.293-4.293a1 1 0 011.414 0z'/%3e%3c/svg%3e\");\n}\n\n[type='radio']:checked {\n  background-image: url(\"data:image/svg+xml,%3csvg viewBox='0 0 16 16' fill='white' xmlns='http://www.w3.org/2000/svg'%3e%3ccircle cx='8' cy='8' r='3'/%3e%3c/svg%3e\");\n}\n\n[type='checkbox']:checked:hover,[type='checkbox']:checked:focus,[type='radio']:checked:hover,[type='radio']:checked:focus {\n  border-color: transparent;\n  background-color: currentColor;\n}\n\n[type='checkbox']:indeterminate {\n  background-image: url(\"data:image/svg+xml,%3csvg xmlns='http://www.w3.org/2000/svg' fill='none' viewBox='0 0 16 16'%3e%3cpath stroke='white' stroke-linecap='round' stroke-linejoin='round' stroke-width='2' d='M4 8h8'/%3e%3c/svg%3e\");\n  border-color: transparent;\n  background-color: currentColor;\n  background-size: 100% 100%;\n  background-position: center;\n  background-repeat: no-repeat;\n}\n\n[type='checkbox']:indeterminate:hover,[type='checkbox']:indeterminate:focus {\n  border-color: transparent;\n  background-color: currentColor;\n}\n\n[type='file'] {\n  background: unset;\n  border-color: inherit;\n  border-width: 0;\n  border-radius: 0;\n  padding: 0;\n  font-size: unset;\n  line-height: inherit;\n}\n\n[type='file']:focus {\n  outline: 1px solid ButtonText;\n  outline: 1px auto -webkit-focus-ring-color;\n}\n\n*, ::before, ::after {\n  --tw-border-spacing-x: 0;\n  --tw-border-spacing-y: 0;\n  --tw-translate-x: 0;\n  --tw-translate-y: 0;\n  --tw-rotate: 0;\n  --tw-skew-x: 0;\n  --tw-skew-y: 0;\n  --tw-scale-x: 1;\n  --tw-scale-y: 1;\n  --tw-pan-x:  ;\n  --tw-pan-y:  ;\n  --tw-pinch-zoom:  ;\n  --tw-scroll-snap-strictness: proximity;\n  --tw-ordinal:  ;\n  --tw-slashed-zero:  ;\n  --tw-numeric-figure:  ;\n  --tw-numeric-spacing:  ;\n  --tw-numeric-fraction:  ;\n  --tw-ring-inset:  ;\n  --tw-ring-offset-width: 0px;\n  --tw-ring-offset-color: #fff;\n  --tw-ring-color: rgb(59 130 246 / 0.5);\n  --tw-ring-offset-shadow: 0 0 #0000;\n  --tw-ring-shadow: 0 0 #0000;\n  --tw-shadow: 0 0 #0000;\n  --tw-shadow-colored: 0 0 #0000;\n  --tw-blur:  ;\n  --tw-brightness:  ;\n  --tw-contrast:  ;\n  --tw-grayscale:  ;\n  --tw-hue-rotate:  ;\n  --tw-invert:  ;\n  --tw-saturate:  ;\n  --tw-sepia:  ;\n  --tw-drop-shadow:  ;\n  --tw-backdrop-blur:  ;\n  --tw-backdrop-brightness:  ;\n  --tw-backdrop-contrast:  ;\n  --tw-backdrop-grayscale:  ;\n  --tw-backdrop-hue-rotate:  ;\n  --tw-backdrop-invert:  ;\n  --tw-backdrop-opacity:  ;\n  --tw-backdrop-saturate:  ;\n  --tw-backdrop-sepia:  ;\n}\n\n::-webkit-backdrop {\n  --tw-border-spacing-x: 0;\n  --tw-border-spacing-y: 0;\n  --tw-translate-x: 0;\n  --tw-translate-y: 0;\n  --tw-rotate: 0;\n  --tw-skew-x: 0;\n  --tw-skew-y: 0;\n  --tw-scale-x: 1;\n  --tw-scale-y: 1;\n  --tw-pan-x:  ;\n  --tw-pan-y:  ;\n  --tw-pinch-zoom:  ;\n  --tw-scroll-snap-strictness: proximity;\n  --tw-ordinal:  ;\n  --tw-slashed-zero:  ;\n  --tw-numeric-figure:  ;\n  --tw-numeric-spacing:  ;\n  --tw-numeric-fraction:  ;\n  --tw-ring-inset:  ;\n  --tw-ring-offset-width: 0px;\n  --tw-ring-offset-color: #fff;\n  --tw-ring-color: rgb(59 130 246 / 0.5);\n  --tw-ring-offset-shadow: 0 0 #0000;\n  --tw-ring-shadow: 0 0 #0000;\n  --tw-shadow: 0 0 #0000;\n  --tw-shadow-colored: 0 0 #0000;\n  --tw-blur:  ;\n  --tw-brightness:  ;\n  --tw-contrast:  ;\n  --tw-grayscale:  ;\n  --tw-hue-rotate:  ;\n  --tw-invert:  ;\n  --tw-saturate:  ;\n  --tw-sepia:  ;\n  --tw-drop-shadow:  ;\n  --tw-backdrop-blur:  ;\n  --tw-backdrop-brightness:  ;\n  --tw-backdrop-contrast:  ;\n  --tw-backdrop-grayscale:  ;\n  --tw-backdrop-hue-rotate:  ;\n  --tw-backdrop-invert:  ;\n  --tw-backdrop-opacity:  ;\n  --tw-backdrop-saturate:  ;\n  --tw-backdrop-sepia:  ;\n}\n\n::backdrop {\n  --tw-border-spacing-x: 0;\n  --tw-border-spacing-y: 0;\n  --tw-translate-x: 0;\n  --tw-translate-y: 0;\n  --tw-rotate: 0;\n  --tw-skew-x: 0;\n  --tw-skew-y: 0;\n  --tw-scale-x: 1;\n  --tw-scale-y: 1;\n  --tw-pan-x:  ;\n  --tw-pan-y:  ;\n  --tw-pinch-zoom:  ;\n  --tw-scroll-snap-strictness: proximity;\n  --tw-ordinal:  ;\n  --tw-slashed-zero:  ;\n  --tw-numeric-figure:  ;\n  --tw-numeric-spacing:  ;\n  --tw-numeric-fraction:  ;\n  --tw-ring-inset:  ;\n  --tw-ring-offset-width: 0px;\n  --tw-ring-offset-color: #fff;\n  --tw-ring-color: rgb(59 130 246 / 0.5);\n  --tw-ring-offset-shadow: 0 0 #0000;\n  --tw-ring-shadow: 0 0 #0000;\n  --tw-shadow: 0 0 #0000;\n  --tw-shadow-colored: 0 0 #0000;\n  --tw-blur:  ;\n  --tw-brightness:  ;\n  --tw-contrast:  ;\n  --tw-grayscale:  ;\n  --tw-hue-rotate:  ;\n  --tw-invert:  ;\n  --tw-saturate:  ;\n  --tw-sepia:  ;\n  --tw-drop-shadow:  ;\n  --tw-backdrop-blur:  ;\n  --tw-backdrop-brightness:  ;\n  --tw-backdrop-contrast:  ;\n  --tw-backdrop-grayscale:  ;\n  --tw-backdrop-hue-rotate:  ;\n  --tw-backdrop-invert:  ;\n  --tw-backdrop-opacity:  ;\n  --tw-backdrop-saturate:  ;\n  --tw-backdrop-sepia:  ;\n}\n\n.sr-only {\n  position: absolute;\n  width: 1px;\n  height: 1px;\n  padding: 0;\n  margin: -1px;\n  overflow: hidden;\n  clip: rect(0, 0, 0, 0);\n  white-space: nowrap;\n  border-width: 0;\n}\n\n.absolute {\n  position: absolute;\n}\n\n.relative {\n  position: relative;\n}\n\n.col-span-6 {\n  grid-column: span 6 / span 6;\n}\n\n.m-2 {\n  margin: 0.5rem;\n}\n\n.mx-auto {\n  margin-left: auto;\n  margin-right: auto;\n}\n\n.my-auto {\n  margin-top: auto;\n  margin-bottom: auto;\n}\n\n.mx-4 {\n  margin-left: 1rem;\n  margin-right: 1rem;\n}\n\n.my-8 {\n  margin-top: 2rem;\n  margin-bottom: 2rem;\n}\n\n.my-3 {\n  margin-top: 0.75rem;\n  margin-bottom: 0.75rem;\n}\n\n.my-2 {\n  margin-top: 0.5rem;\n  margin-bottom: 0.5rem;\n}\n\n.mt-2 {\n  margin-top: 0.5rem;\n}\n\n.mb-2 {\n  margin-bottom: 0.5rem;\n}\n\n.mt-1 {\n  margin-top: 0.25rem;\n}\n\n.mb-1 {\n  margin-bottom: 0.25rem;\n}\n\n.mb-6 {\n  margin-bottom: 1.5rem;\n}\n\n.mt-auto {\n  margin-top: auto;\n}\n\n.mb-5 {\n  margin-bottom: 1.25rem;\n}\n\n.mr-auto {\n  margin-right: auto;\n}\n\n.mr-2 {\n  margin-right: 0.5rem;\n}\n\n.ml-2 {\n  margin-left: 0.5rem;\n}\n\n.ml-4 {\n  margin-left: 1rem;\n}\n\n.mr-4 {\n  margin-right: 1rem;\n}\n\n.mb-0 {\n  margin-bottom: 0px;\n}\n\n.mb-4 {\n  margin-bottom: 1rem;\n}\n\n.ml-auto {\n  margin-left: auto;\n}\n\n.mt-\\[6px\\] {\n  margin-top: 6px;\n}\n\n.mt-\\[5px\\] {\n  margin-top: 5px;\n}\n\n.mb-3 {\n  margin-bottom: 0.75rem;\n}\n\n.mt-3 {\n  margin-top: 0.75rem;\n}\n\n.mt-5 {\n  margin-top: 1.25rem;\n}\n\n.block {\n  display: block;\n}\n\n.flex {\n  display: flex;\n}\n\n.inline-flex {\n  display: inline-flex;\n}\n\n.table {\n  display: table;\n}\n\n.grid {\n  display: grid;\n}\n\n.hidden {\n  display: none;\n}\n\n.h-screen {\n  height: 100vh;\n}\n\n.w-screen {\n  width: 100vw;\n}\n\n.w-full {\n  width: 100%;\n}\n\n.w-auto {\n  width: auto;\n}\n\n.w-16 {\n  width: 4rem;\n}\n\n.max-w-sm {\n  max-width: 24rem;\n}\n\n.border-collapse {\n  border-collapse: collapse;\n}\n\n.grid-cols-2 {\n  grid-template-columns: repeat(2, minmax(0, 1fr));\n}\n\n.flex-row {\n  flex-direction: row;\n}\n\n.flex-col {\n  flex-direction: column;\n}\n\n.content-center {\n  align-content: center;\n}\n\n.items-center {\n  align-items: center;\n}\n\n.justify-center {\n  justify-content: center;\n}\n\n.space-y-0 > :not([hidden]) ~ :not([hidden]) {\n  --tw-space-y-reverse: 0;\n  margin-top: calc(0px * calc(1 - var(--tw-space-y-reverse)));\n  margin-bottom: calc(0px * var(--tw-space-y-reverse));\n}\n\n.overflow-hidden {\n  overflow: hidden;\n}\n\n.overflow-x-auto {\n  overflow-x: auto;\n}\n\n.rounded-lg {\n  border-radius: 0.5rem;\n}\n\n.rounded-none {\n  border-radius: 0px;\n}\n\n.rounded-b-md {\n  border-bottom-right-radius: 0.375rem;\n  border-bottom-left-radius: 0.375rem;\n}\n\n.border {\n  border-width: 1px;\n}\n\n.border-b {\n  border-bottom-width: 1px;\n}\n\n.border-transparent {\n  border-color: transparent;\n}\n\n.border-neutral-100 {\n  --tw-border-opacity: 1;\n  border-color: rgb(245 245 245 / var(--tw-border-opacity));\n}\n\n.border-neutral-200 {\n  --tw-border-opacity: 1;\n  border-color: rgb(229 229 229 / var(--tw-border-opacity));\n}\n\n.border-white {\n  --tw-border-opacity: 1;\n  border-color: rgb(255 255 255 / var(--tw-border-opacity));\n}\n\n.border-gray-300 {\n  --tw-border-opacity: 1;\n  border-color: rgb(209 213 219 / var(--tw-border-opacity));\n}\n\n.bg-white {\n  --tw-bg-opacity: 1;\n  background-color: rgb(255 255 255 / var(--tw-bg-opacity));\n}\n\n.bg-blue-500 {\n  --tw-bg-opacity: 1;\n  background-color: rgb(59 130 246 / var(--tw-bg-opacity));\n}\n\n.bg-gray-50 {\n  --tw-bg-opacity: 1;\n  background-color: rgb(249 250 251 / var(--tw-bg-opacity));\n}\n\n.bg-blue-600 {\n  --tw-bg-opacity: 1;\n  background-color: rgb(37 99 235 / var(--tw-bg-opacity));\n}\n\n.bg-neutral-100 {\n  --tw-bg-opacity: 1;\n  background-color: rgb(245 245 245 / var(--tw-bg-opacity));\n}\n\n.bg-gradient-to-br {\n  background-image: linear-gradient(to bottom right, var(--tw-gradient-stops));\n}\n\n.from-pink-500 {\n  --tw-gradient-from: #ec4899;\n  --tw-gradient-to: rgb(236 72 153 / 0);\n  --tw-gradient-stops: var(--tw-gradient-from), var(--tw-gradient-to);\n}\n\n.from-violet-500 {\n  --tw-gradient-from: #8b5cf6;\n  --tw-gradient-to: rgb(139 92 246 / 0);\n  --tw-gradient-stops: var(--tw-gradient-from), var(--tw-gradient-to);\n}\n\n.from-neutral-600 {\n  --tw-gradient-from: #525252;\n  --tw-gradient-to: rgb(82 82 82 / 0);\n  --tw-gradient-stops: var(--tw-gradient-from), var(--tw-gradient-to);\n}\n\n.from-green-500 {\n  --tw-gradient-from: #22c55e;\n  --tw-gradient-to: rgb(34 197 94 / 0);\n  --tw-gradient-stops: var(--tw-gradient-from), var(--tw-gradient-to);\n}\n\n.from-blue-500 {\n  --tw-gradient-from: #3b82f6;\n  --tw-gradient-to: rgb(59 130 246 / 0);\n  --tw-gradient-stops: var(--tw-gradient-from), var(--tw-gradient-to);\n}\n\n.from-red-500 {\n  --tw-gradient-from: #ef4444;\n  --tw-gradient-to: rgb(239 68 68 / 0);\n  --tw-gradient-stops: var(--tw-gradient-from), var(--tw-gradient-to);\n}\n\n.to-pink-300 {\n  --tw-gradient-to: #f9a8d4;\n}\n\n.to-violet-300 {\n  --tw-gradient-to: #c4b5fd;\n}\n\n.to-neutral-400 {\n  --tw-gradient-to: #a3a3a3;\n}\n\n.to-green-300 {\n  --tw-gradient-to: #86efac;\n}\n\n.to-blue-300 {\n  --tw-gradient-to: #93c5fd;\n}\n\n.to-red-300 {\n  --tw-gradient-to: #fca5a5;\n}\n\n.p-2 {\n  padding: 0.5rem;\n}\n\n.px-6 {\n  padding-left: 1.5rem;\n  padding-right: 1.5rem;\n}\n\n.py-4 {\n  padding-top: 1rem;\n  padding-bottom: 1rem;\n}\n\n.px-4 {\n  padding-left: 1rem;\n  padding-right: 1rem;\n}\n\n.py-5 {\n  padding-top: 1.25rem;\n  padding-bottom: 1.25rem;\n}\n\n.py-2 {\n  padding-top: 0.5rem;\n  padding-bottom: 0.5rem;\n}\n\n.py-20 {\n  padding-top: 5rem;\n  padding-bottom: 5rem;\n}\n\n.py-\\[6px\\] {\n  padding-top: 6px;\n  padding-bottom: 6px;\n}\n\n.px-0 {\n  padding-left: 0px;\n  padding-right: 0px;\n}\n\n.px-3 {\n  padding-left: 0.75rem;\n  padding-right: 0.75rem;\n}\n\n.py-1 {\n  padding-top: 0.25rem;\n  padding-bottom: 0.25rem;\n}\n\n.py-\\[8px\\] {\n  padding-top: 8px;\n  padding-bottom: 8px;\n}\n\n.px-8 {\n  padding-left: 2rem;\n  padding-right: 2rem;\n}\n\n.py-\\[2px\\] {\n  padding-top: 2px;\n  padding-bottom: 2px;\n}\n\n.px-5 {\n  padding-left: 1.25rem;\n  padding-right: 1.25rem;\n}\n\n.pr-3 {\n  padding-right: 0.75rem;\n}\n\n.pr-4 {\n  padding-right: 1rem;\n}\n\n.text-right {\n  text-align: right;\n}\n\n.text-2xl {\n  font-size: 1.5rem;\n  line-height: 2rem;\n}\n\n.text-sm {\n  font-size: 0.875rem;\n  line-height: 1.25rem;\n}\n\n.text-lg {\n  font-size: 1.125rem;\n  line-height: 1.75rem;\n}\n\n.font-semibold {\n  font-weight: 600;\n}\n\n.font-medium {\n  font-weight: 500;\n}\n\n.font-bold {\n  font-weight: 700;\n}\n\n.leading-6 {\n  line-height: 1.5rem;\n}\n\n.text-white {\n  --tw-text-opacity: 1;\n  color: rgb(255 255 255 / var(--tw-text-opacity));\n}\n\n.text-neutral-100 {\n  --tw-text-opacity: 1;\n  color: rgb(245 245 245 / var(--tw-text-opacity));\n}\n\n.text-neutral-600 {\n  --tw-text-opacity: 1;\n  color: rgb(82 82 82 / var(--tw-text-opacity));\n}\n\n.text-blue-500 {\n  --tw-text-opacity: 1;\n  color: rgb(59 130 246 / var(--tw-text-opacity));\n}\n\n.text-gray-900 {\n  --tw-text-opacity: 1;\n  color: rgb(17 24 39 / var(--tw-text-opacity));\n}\n\n.text-gray-700 {\n  --tw-text-opacity: 1;\n  color: rgb(55 65 81 / var(--tw-text-opacity));\n}\n\n.text-gray-500 {\n  --tw-text-opacity: 1;\n  color: rgb(107 114 128 / var(--tw-text-opacity));\n}\n\n.shadow-sm {\n  --tw-shadow: 0 1px 2px 0 rgb(0 0 0 / 0.05);\n  --tw-shadow-colored: 0 1px 2px 0 var(--tw-shadow-color);\n  box-shadow: var(--tw-ring-offset-shadow, 0 0 #0000), var(--tw-ring-shadow, 0 0 #0000), var(--tw-shadow);\n}\n\n.shadow-lg {\n  --tw-shadow: 0 10px 15px -3px rgb(0 0 0 / 0.1), 0 4px 6px -4px rgb(0 0 0 / 0.1);\n  --tw-shadow-colored: 0 10px 15px -3px var(--tw-shadow-color), 0 4px 6px -4px var(--tw-shadow-color);\n  box-shadow: var(--tw-ring-offset-shadow, 0 0 #0000), var(--tw-ring-shadow, 0 0 #0000), var(--tw-shadow);\n}\n\n.shadow {\n  --tw-shadow: 0 1px 3px 0 rgb(0 0 0 / 0.1), 0 1px 2px -1px rgb(0 0 0 / 0.1);\n  --tw-shadow-colored: 0 1px 3px 0 var(--tw-shadow-color), 0 1px 2px -1px var(--tw-shadow-color);\n  box-shadow: var(--tw-ring-offset-shadow, 0 0 #0000), var(--tw-ring-shadow, 0 0 #0000), var(--tw-shadow);\n}\n\n.outline-none {\n  outline: 2px solid transparent;\n  outline-offset: 2px;\n}\n\n.font-jost {\n  font-family: \"Jost\";\n}\n\n.font-inter {\n  font-family: \"Inter\";\n}\n\n.code {\n  font-family: \"Source Code Pro\", monospace;\n  display: block;\n  background-color: white;\n  color: #000000;\n  padding: 1em;\n  word-wrap: break-word;\n  white-space: pre-wrap;\n}\n\n.sidenav {\n  height: 100%;\n  /* 100% Full-height */\n  width: 0;\n  /* 0 width - change this with JavaScript */\n  position: fixed;\n  /* Stay in place */\n  z-index: 1;\n  /* Stay on top */\n  top: 0;\n  /* Stay at the top */\n  left: 0;\n  overflow-x: hidden;\n  /* Disable horizontal scroll */\n  padding-top: 60px;\n  /* Place content 60px from the top */\n  transition: 0.5s;\n  /* 0.5 second transition effect to slide in the sidenav */\n}\n\n/* The navigation menu links */\n\n.sidenav a {\n  display: block;\n}\n\nselect {\n  -webkit-appearance: none;\n     -moz-appearance: none;\n          appearance: none;\n  background-color: #fff;\n  border-color: #6b7280;\n  border-width: 1px;\n  border-radius: 0px;\n  padding-top: 0.5rem;\n  padding-right: 0.75rem;\n  padding-bottom: 0.5rem;\n  padding-left: 0.75rem;\n  font-size: 1rem;\n  line-height: 1.5rem;\n  --tw-shadow: 0 0 #0000;\n}\n\n select:focus {\n  outline: 2px solid transparent;\n  outline-offset: 2px;\n  --tw-ring-inset: var(--tw-empty,/*!*/ /*!*/);\n  --tw-ring-offset-width: 0px;\n  --tw-ring-offset-color: #fff;\n  --tw-ring-color: #2563eb;\n  --tw-ring-offset-shadow: var(--tw-ring-inset) 0 0 0 var(--tw-ring-offset-width) var(--tw-ring-offset-color);\n  --tw-ring-shadow: var(--tw-ring-inset) 0 0 0 calc(1px + var(--tw-ring-offset-width)) var(--tw-ring-color);\n  box-shadow: var(--tw-ring-offset-shadow), var(--tw-ring-shadow), var(--tw-shadow);\n  border-color: #2563eb;\n}\n\nselect {\n  background-image: url(\"data:image/svg+xml,%3csvg xmlns='http://www.w3.org/2000/svg' fill='none' viewBox='0 0 20 20'%3e%3cpath stroke='%236b7280' stroke-linecap='round' stroke-linejoin='round' stroke-width='1.5' d='M6 8l4 4 4-4'/%3e%3c/svg%3e\");\n  background-position: right 0.5rem center;\n  background-size: 1.5em 1.5em;\n  -webkit-print-color-adjust: exact;\n     color-adjust: exact;\n          print-color-adjust: exact;\n  margin: 0px;\n  margin-top: 0.5rem;\n  display: block;\n  width: 100%;\n  -webkit-appearance: none;\n     -moz-appearance: none;\n          appearance: none;\n  border-radius: 0.25rem;\n  border-width: 1px;\n  border-style: solid;\n  --tw-border-opacity: 1;\n  border-color: rgb(209 213 219 / var(--tw-border-opacity));\n  --tw-bg-opacity: 1;\n  background-color: rgb(255 255 255 / var(--tw-bg-opacity));\n  background-clip: padding-box;\n  background-repeat: no-repeat;\n  padding-left: 0.75rem;\n  padding-right: 0.75rem;\n  padding-top: 0.375rem;\n  padding-bottom: 0.375rem;\n  font-size: 1rem;\n  line-height: 1.5rem;\n  font-weight: 400;\n  --tw-text-opacity: 1;\n  color: rgb(55 65 81 / var(--tw-text-opacity));\n  transition-property: color, background-color, border-color, fill, stroke, opacity, box-shadow, transform, filter, -webkit-text-decoration-color, -webkit-backdrop-filter;\n  transition-property: color, background-color, border-color, text-decoration-color, fill, stroke, opacity, box-shadow, transform, filter, backdrop-filter;\n  transition-property: color, background-color, border-color, text-decoration-color, fill, stroke, opacity, box-shadow, transform, filter, backdrop-filter, -webkit-text-decoration-color, -webkit-backdrop-filter;\n  transition-duration: 150ms;\n  transition-timing-function: cubic-bezier(0.4, 0, 0.2, 1);\n}\n\nselect:focus {\n  --tw-border-opacity: 1;\n  border-color: rgb(37 99 235 / var(--tw-border-opacity));\n  --tw-bg-opacity: 1;\n  background-color: rgb(255 255 255 / var(--tw-bg-opacity));\n  --tw-text-opacity: 1;\n  color: rgb(55 65 81 / var(--tw-text-opacity));\n  outline: 2px solid transparent;\n  outline-offset: 2px;\n}\n\n/* Position and style the close button (top right corner) */\n\n.sidenav .closebtn {\n  position: absolute;\n  top: 0;\n  right: 25px;\n  font-size: 28px;\n  margin-left: 50px;\n}\n\n@media screen and (max-height: 450px) {\n  .sidenav {\n    padding-top: 15px;\n  }\n\n  .sidenav a {\n    font-size: 18px;\n  }\n}\n\n.file\\:mr-4::-webkit-file-upload-button {\n  margin-right: 1rem;\n}\n\n.file\\:mr-4::file-selector-button {\n  margin-right: 1rem;\n}\n\n.file\\:rounded-full::-webkit-file-upload-button {\n  border-radius: 9999px;\n}\n\n.file\\:rounded-full::file-selector-button {\n  border-radius: 9999px;\n}\n\n.file\\:border-0::-webkit-file-upload-button {\n  border-width: 0px;\n}\n\n.file\\:border-0::file-selector-button {\n  border-width: 0px;\n}\n\n.file\\:bg-blue-50::-webkit-file-upload-button {\n  --tw-bg-opacity: 1;\n  background-color: rgb(239 246 255 / var(--tw-bg-opacity));\n}\n\n.file\\:bg-blue-50::file-selector-button {\n  --tw-bg-opacity: 1;\n  background-color: rgb(239 246 255 / var(--tw-bg-opacity));\n}\n\n.file\\:py-2::-webkit-file-upload-button {\n  padding-top: 0.5rem;\n  padding-bottom: 0.5rem;\n}\n\n.file\\:py-2::file-selector-button {\n  padding-top: 0.5rem;\n  padding-bottom: 0.5rem;\n}\n\n.file\\:px-4::-webkit-file-upload-button {\n  padding-left: 1rem;\n  padding-right: 1rem;\n}\n\n.file\\:px-4::file-selector-button {\n  padding-left: 1rem;\n  padding-right: 1rem;\n}\n\n.file\\:text-sm::-webkit-file-upload-button {\n  font-size: 0.875rem;\n  line-height: 1.25rem;\n}\n\n.file\\:text-sm::file-selector-button {\n  font-size: 0.875rem;\n  line-height: 1.25rem;\n}\n\n.file\\:font-semibold::-webkit-file-upload-button {\n  font-weight: 600;\n}\n\n.file\\:font-semibold::file-selector-button {\n  font-weight: 600;\n}\n\n.file\\:text-blue-700::-webkit-file-upload-button {\n  --tw-text-opacity: 1;\n  color: rgb(29 78 216 / var(--tw-text-opacity));\n}\n\n.file\\:text-blue-700::file-selector-button {\n  --tw-text-opacity: 1;\n  color: rgb(29 78 216 / var(--tw-text-opacity));\n}\n\n.hover\\:bg-blue-700:hover {\n  --tw-bg-opacity: 1;\n  background-color: rgb(29 78 216 / var(--tw-bg-opacity));\n}\n\n.hover\\:bg-blue-400:hover {\n  --tw-bg-opacity: 1;\n  background-color: rgb(96 165 250 / var(--tw-bg-opacity));\n}\n\n.hover\\:file\\:bg-blue-100::-webkit-file-upload-button:hover {\n  --tw-bg-opacity: 1;\n  background-color: rgb(219 234 254 / var(--tw-bg-opacity));\n}\n\n.hover\\:file\\:bg-blue-100::file-selector-button:hover {\n  --tw-bg-opacity: 1;\n  background-color: rgb(219 234 254 / var(--tw-bg-opacity));\n}\n\n.focus\\:border-blue-500:focus {\n  --tw-border-opacity: 1;\n  border-color: rgb(59 130 246 / var(--tw-border-opacity));\n}\n\n.focus\\:border-indigo-500:focus {\n  --tw-border-opacity: 1;\n  border-color: rgb(99 102 241 / var(--tw-border-opacity));\n}\n\n.focus\\:outline-none:focus {\n  outline: 2px solid transparent;\n  outline-offset: 2px;\n}\n\n.focus\\:ring-2:focus {\n  --tw-ring-offset-shadow: var(--tw-ring-inset) 0 0 0 var(--tw-ring-offset-width) var(--tw-ring-offset-color);\n  --tw-ring-shadow: var(--tw-ring-inset) 0 0 0 calc(2px + var(--tw-ring-offset-width)) var(--tw-ring-color);\n  box-shadow: var(--tw-ring-offset-shadow), var(--tw-ring-shadow), var(--tw-shadow, 0 0 #0000);\n}\n\n.focus\\:ring-indigo-500:focus {\n  --tw-ring-opacity: 1;\n  --tw-ring-color: rgb(99 102 241 / var(--tw-ring-opacity));\n}\n\n.focus\\:ring-blue-500:focus {\n  --tw-ring-opacity: 1;\n  --tw-ring-color: rgb(59 130 246 / var(--tw-ring-opacity));\n}\n\n.focus\\:ring-offset-2:focus {\n  --tw-ring-offset-width: 2px;\n}\n\n@media (min-width: 640px) {\n  .sm\\:col-span-3 {\n    grid-column: span 3 / span 3;\n  }\n\n  .sm\\:p-6 {\n    padding: 1.5rem;\n  }\n\n  .sm\\:px-6 {\n    padding-left: 1.5rem;\n    padding-right: 1.5rem;\n  }\n\n  .sm\\:py-0 {\n    padding-top: 0px;\n    padding-bottom: 0px;\n  }\n\n  .sm\\:px-4 {\n    padding-left: 1rem;\n    padding-right: 1rem;\n  }\n\n  .sm\\:pt-2 {\n    padding-top: 0.5rem;\n  }\n\n  .sm\\:pr-4 {\n    padding-right: 1rem;\n  }\n\n  .sm\\:text-sm {\n    font-size: 0.875rem;\n    line-height: 1.25rem;\n  }\n\n  .sm\\:font-semibold {\n    font-weight: 600;\n  }\n}\n\n@media (min-width: 768px) {\n  .md\\:mr-0 {\n    margin-right: 0px;\n  }\n\n  .md\\:mb-2 {\n    margin-bottom: 0.5rem;\n  }\n\n  .md\\:ml-0 {\n    margin-left: 0px;\n  }\n\n  .md\\:inline-flex {\n    display: inline-flex;\n  }\n\n  .md\\:grid-cols-3 {\n    grid-template-columns: repeat(3, minmax(0, 1fr));\n  }\n\n  .md\\:flex-col {\n    flex-direction: column;\n  }\n\n  .md\\:items-center {\n    align-items: center;\n  }\n\n  .md\\:space-y-4 > :not([hidden]) ~ :not([hidden]) {\n    --tw-space-y-reverse: 0;\n    margin-top: calc(1rem * calc(1 - var(--tw-space-y-reverse)));\n    margin-bottom: calc(1rem * var(--tw-space-y-reverse));\n  }\n\n  .md\\:py-\\[6px\\] {\n    padding-top: 6px;\n    padding-bottom: 6px;\n  }\n\n  .md\\:py-8 {\n    padding-top: 2rem;\n    padding-bottom: 2rem;\n  }\n\n  .md\\:text-left {\n    text-align: left;\n  }\n\n  .md\\:text-lg {\n    font-size: 1.125rem;\n    line-height: 1.75rem;\n  }\n\n  .md\\:text-5xl {\n    font-size: 3rem;\n    line-height: 1;\n  }\n}\n\n@media (min-width: 1024px) {\n  .lg\\:mx-auto {\n    margin-left: auto;\n    margin-right: auto;\n  }\n\n  .lg\\:my-auto {\n    margin-top: auto;\n    margin-bottom: auto;\n  }\n\n  .lg\\:my-5 {\n    margin-top: 1.25rem;\n    margin-bottom: 1.25rem;\n  }\n\n  .lg\\:mb-0 {\n    margin-bottom: 0px;\n  }\n\n  .lg\\:mt-2 {\n    margin-top: 0.5rem;\n  }\n\n  .lg\\:mb-5 {\n    margin-bottom: 1.25rem;\n  }\n\n  .lg\\:mb-2 {\n    margin-bottom: 0.5rem;\n  }\n\n  .lg\\:w-1\\/3 {\n    width: 33.333333%;\n  }\n\n  .lg\\:w-1\\/2 {\n    width: 50%;\n  }\n\n  .lg\\:rounded-t-md {\n    border-top-left-radius: 0.375rem;\n    border-top-right-radius: 0.375rem;\n  }\n\n  .lg\\:py-20 {\n    padding-top: 5rem;\n    padding-bottom: 5rem;\n  }\n\n  .lg\\:py-1 {\n    padding-top: 0.25rem;\n    padding-bottom: 0.25rem;\n  }\n\n  .lg\\:px-6 {\n    padding-left: 1.5rem;\n    padding-right: 1.5rem;\n  }\n\n  .lg\\:px-0 {\n    padding-left: 0px;\n    padding-right: 0px;\n  }\n\n  .lg\\:text-lg {\n    font-size: 1.125rem;\n    line-height: 1.75rem;\n  }\n}\n",
            ],
            sourceRoot: "",
          },
        ]);
        const E = h;
      },
      645: (e) => {
        "use strict";
        e.exports = function (e) {
          var t = [];
          return (
            (t.toString = function () {
              return this.map(function (t) {
                var n = "",
                  r = void 0 !== t[5];
                return (
                  t[4] && (n += "@supports (".concat(t[4], ") {")),
                  t[2] && (n += "@media ".concat(t[2], " {")),
                  r &&
                    (n += "@layer".concat(
                      t[5].length > 0 ? " ".concat(t[5]) : "",
                      " {"
                    )),
                  (n += e(t)),
                  r && (n += "}"),
                  t[2] && (n += "}"),
                  t[4] && (n += "}"),
                  n
                );
              }).join("");
            }),
            (t.i = function (e, n, r, i, o) {
              "string" == typeof e && (e = [[null, e, void 0]]);
              var s = {};
              if (r)
                for (var a = 0; a < this.length; a++) {
                  var c = this[a][0];
                  null != c && (s[c] = !0);
                }
              for (var l = 0; l < e.length; l++) {
                var A = [].concat(e[l]);
                (r && s[A[0]]) ||
                  (void 0 !== o &&
                    (void 0 === A[5] ||
                      (A[1] = "@layer"
                        .concat(A[5].length > 0 ? " ".concat(A[5]) : "", " {")
                        .concat(A[1], "}")),
                    (A[5] = o)),
                  n &&
                    (A[2]
                      ? ((A[1] = "@media "
                          .concat(A[2], " {")
                          .concat(A[1], "}")),
                        (A[2] = n))
                      : (A[2] = n)),
                  i &&
                    (A[4]
                      ? ((A[1] = "@supports ("
                          .concat(A[4], ") {")
                          .concat(A[1], "}")),
                        (A[4] = i))
                      : (A[4] = "".concat(i))),
                  t.push(A));
              }
            }),
            t
          );
        };
      },
      667: (e) => {
        "use strict";
        e.exports = function (e, t) {
          return (
            t || (t = {}),
            e
              ? ((e = String(e.__esModule ? e.default : e)),
                /^['"].*['"]$/.test(e) && (e = e.slice(1, -1)),
                t.hash && (e += t.hash),
                /["'() \t\n]|(%20)/.test(e) || t.needQuotes
                  ? '"'.concat(
                      e.replace(/"/g, '\\"').replace(/\n/g, "\\n"),
                      '"'
                    )
                  : e)
              : e
          );
        };
      },
      537: (e) => {
        "use strict";
        e.exports = function (e) {
          var t = e[1],
            n = e[3];
          if (!n) return t;
          if ("function" == typeof btoa) {
            var r = btoa(unescape(encodeURIComponent(JSON.stringify(n)))),
              i =
                "sourceMappingURL=data:application/json;charset=utf-8;base64,".concat(
                  r
                ),
              o = "/*# ".concat(i, " */"),
              s = n.sources.map(function (e) {
                return "/*# sourceURL="
                  .concat(n.sourceRoot || "")
                  .concat(e, " */");
              });
            return [t].concat(s).concat([o]).join("\n");
          }
          return [t].join("\n");
        };
      },
      284: (e) => {
        var t = function () {
          if ("object" == typeof self && self) return self;
          if ("object" == typeof window && window) return window;
          throw new Error("Unable to resolve global `this`");
        };
        e.exports = (function () {
          if (this) return this;
          if ("object" == typeof globalThis && globalThis) return globalThis;
          try {
            Object.defineProperty(Object.prototype, "__global__", {
              get: function () {
                return this;
              },
              configurable: !0,
            });
          } catch (e) {
            return t();
          }
          try {
            return __global__ || t();
          } finally {
            delete Object.prototype.__global__;
          }
        })();
      },
      514: (e) => {
        e.exports = window.FormData;
      },
      811: (e, t) => {
        "use strict";
        Object.defineProperty(t, "__esModule", { value: !0 });
        var n = (function () {
            function e(e, t) {
              for (var n = 0; n < t.length; n++) {
                var r = t[n];
                (r.enumerable = r.enumerable || !1),
                  (r.configurable = !0),
                  "value" in r && (r.writable = !0),
                  Object.defineProperty(e, r.key, r);
              }
            }
            return function (t, n, r) {
              return n && e(t.prototype, n), r && e(t, r), t;
            };
          })(),
          r = (function () {
            function e() {
              !(function (e, t) {
                if (!(e instanceof t))
                  throw new TypeError("Cannot call a class as a function");
              })(this, e);
            }
            return (
              n(e, [
                {
                  key: "when",
                  value: function (e) {
                    var t = this,
                      n =
                        arguments.length <= 1 || void 0 === arguments[1]
                          ? null
                          : arguments[1];
                    if (
                      ((this._eventListeners = this._eventListeners || {}),
                      (this._eventListeners[e] = this._eventListeners[e] || []),
                      !n)
                    )
                      return new Promise(function (n, r) {
                        (n._removeAfterCall = !0), t._eventListeners[e].push(n);
                      });
                    this._eventListeners[e].push(n);
                  },
                },
                {
                  key: "on",
                  value: function () {
                    return this.when.apply(this, arguments);
                  },
                },
                {
                  key: "addEventListener",
                  value: function () {
                    return this.when.apply(this, arguments);
                  },
                },
                {
                  key: "emit",
                  value: function (e) {
                    for (
                      var t =
                          (this._eventListeners && this._eventListeners[e]) ||
                          [],
                        n = arguments.length,
                        r = Array(n > 1 ? n - 1 : 0),
                        i = 1;
                      i < n;
                      i++
                    )
                      r[i - 1] = arguments[i];
                    var o = !0,
                      s = !1,
                      a = void 0;
                    try {
                      for (
                        var c, l = t[Symbol.iterator]();
                        !(o = (c = l.next()).done);
                        o = !0
                      ) {
                        var A = c.value;
                        A.apply(this, r);
                      }
                    } catch (e) {
                      (s = !0), (a = e);
                    } finally {
                      try {
                        !o && l.return && l.return();
                      } finally {
                        if (s) throw a;
                      }
                    }
                    for (var d = 0; d < t.length; d++)
                      t[d]._removeAfterCall && t.splice(d--, 1);
                  },
                },
                {
                  key: "trigger",
                  value: function () {
                    return this.emit.apply(this, arguments);
                  },
                },
                {
                  key: "triggerEvent",
                  value: function () {
                    return this.emit.apply(this, arguments);
                  },
                },
              ]),
              e
            );
          })();
        (t.default = r),
          (r.mixin = function (e) {
            for (var t in r.prototype)
              r.prototype.hasOwnProperty(t) && (e[t] = r.prototype[t]);
          }),
          (e.exports = t.default);
      },
      585: (e, t) => {
        "use strict";
        Object.defineProperty(t, "__esModule", { value: !0 }),
          (t.default = {
            Information:
              "data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiIHN0YW5kYWxvbmU9Im5vIj8+Cjxzdmcgd2lkdGg9IjgwcHgiIGhlaWdodD0iODBweCIgdmlld0JveD0iMCAwIDgwIDgwIiB2ZXJzaW9uPSIxLjEiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIgeG1sbnM6eGxpbms9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkveGxpbmsiPgogICAgPCEtLSBHZW5lcmF0b3I6IFNrZXRjaCAzLjguMyAoMjk4MDIpIC0gaHR0cDovL3d3dy5ib2hlbWlhbmNvZGluZy5jb20vc2tldGNoIC0tPgogICAgPHRpdGxlPkluZm9ybWF0aW9uIEljb248L3RpdGxlPgogICAgPGRlc2M+Q3JlYXRlZCB3aXRoIFNrZXRjaC48L2Rlc2M+CiAgICA8ZGVmcz48L2RlZnM+CiAgICA8ZyBpZD0iUGFnZS0xIiBzdHJva2U9Im5vbmUiIHN0cm9rZS13aWR0aD0iMSIgZmlsbD0ibm9uZSIgZmlsbC1ydWxlPSJldmVub2RkIj4KICAgICAgICA8ZyBpZD0iSW5mb3JtYXRpb24tSWNvbiIgZmlsbD0iIzAwODVGRiI+CiAgICAgICAgICAgIDxnIGlkPSI3MjQtaW5mb0AyeCIgdHJhbnNmb3JtPSJ0cmFuc2xhdGUoNi4wMDAwMDAsIDYuMDAwMDAwKSI+CiAgICAgICAgICAgICAgICA8ZyBpZD0iTGF5ZXJfMSI+CiAgICAgICAgICAgICAgICAgICAgPGcgaWQ9Il94MzdfMjQtaW5mb194NDBfMngucG5nIj4KICAgICAgICAgICAgICAgICAgICAgICAgPHBhdGggZD0iTTMzLjczNDA3MTQsMjUuNzA3NjQyOSBDMzQuNzE4ODU3MSwyNS43MDc2NDI5IDM1LjU3MTI4NTcsMjUuMzQzMzU3MSAzNi4yOTAxNDI5LDI0LjYxNzIxNDMgQzM3LjAwOSwyMy44OTEwNzE0IDM3LjM3MDg1NzEsMjMuMDA5NSAzNy4zNzA4NTcxLDIxLjk3NjE0MjkgQzM3LjM3MDg1NzEsMjAuOTQyNzg1NyAzNy4wMTM4NTcxLDIwLjA2IDM2LjI5OTg1NzEsMTkuMzI1MzU3MSBDMzUuNTg1ODU3MSwxOC41OTA3MTQzIDM0LjczMSwxOC4yMjUyMTQzIDMzLjczNDA3MTQsMTguMjI1MjE0MyBDMzIuNzM3MTQyOSwxOC4yMjUyMTQzIDMxLjg3ODY0MjksMTguNTkxOTI4NiAzMS4xNTg1NzE0LDE5LjMyNTM1NzEgQzMwLjQzODUsMjAuMDU4Nzg1NyAzMC4wNzkwNzE0LDIwLjk0Mjc4NTcgMzAuMDc5MDcxNCwyMS45NzYxNDI5IEMzMC4wNzkwNzE0LDIzLjAwOTUgMzAuNDM4NSwyMy44ODk4NTcxIDMxLjE1ODU3MTQsMjQuNjE3MjE0MyBDMzEuODc4NjQyOSwyNS4zNDQ1NzE0IDMyLjczNzE0MjksMjUuNzA3NjQyOSAzMy43MzQwNzE0LDI1LjcwNzY0MjkgTDMzLjczNDA3MTQsMjUuNzA3NjQyOSBaIE0zNCwwIEMxNS4yMjIyODU3LDAgMCwxNS4yMjIyODU3IDAsMzQgQzAsNTIuNzc3NzE0MyAxNS4yMjIyODU3LDY4IDM0LDY4IEM1Mi43Nzc3MTQzLDY4IDY4LDUyLjc3NzcxNDMgNjgsMzQgQzY4LDE1LjIyMjI4NTcgNTIuNzc3NzE0MywwIDM0LDAgTDM0LDAgWiBNMzQsNjUuNTcxNDI4NiBDMTYuNTY0MDcxNCw2NS41NzE0Mjg2IDIuNDI4NTcxNDMsNTEuNDM1OTI4NiAyLjQyODU3MTQzLDM0IEMyLjQyODU3MTQzLDE2LjU2NDA3MTQgMTYuNTY0MDcxNCwyLjQyODU3MTQzIDM0LDIuNDI4NTcxNDMgQzUxLjQzNTkyODYsMi40Mjg1NzE0MyA2NS41NzE0Mjg2LDE2LjU2NDA3MTQgNjUuNTcxNDI4NiwzNCBDNjUuNTcxNDI4Niw1MS40MzU5Mjg2IDUxLjQzNTkyODYsNjUuNTcxNDI4NiAzNCw2NS41NzE0Mjg2IEwzNCw2NS41NzE0Mjg2IFogTTM4LjMzMDE0MjksNDcuNzY3NTcxNCBDMzcuOTg2NSw0Ny42MDM2NDI5IDM3LjcyMDU3MTQsNDcuMzU1OTI4NiAzNy41MzcyMTQzLDQ3LjAyMzIxNDMgQzM3LjM1MjY0MjksNDYuNjkxNzE0MyAzNy4yNTkxNDI5LDQ2LjI4NzM1NzEgMzcuMjU5MTQyOSw0NS44MTAxNDI5IEwzNy4yNTkxNDI5LDI5LjYyMjUgTDM2Ljk4MjI4NTcsMjkuMzE2NSBMMjcuOTM3MDcxNCwyOS44NDcxNDI5IEwyNy45MzcwNzE0LDMxLjMzNTg1NzEgQzI4LjMwNjIxNDMsMzEuMzc1OTI4NiAyOC43MTU0Mjg2LDMxLjQ3MTg1NzEgMjkuMTY0NzE0MywzMS42MjEyMTQzIEMyOS42MTQsMzEuNzcwNTcxNCAyOS45NDkxNDI5LDMxLjkyNzIxNDMgMzAuMTcwMTQyOSwzMi4wODk5Mjg2IEMzMC40NjUyMTQzLDMyLjMwODUgMzAuNzExNzE0MywzMi41OTYyODU3IDMwLjkwODQyODYsMzIuOTU2OTI4NiBDMzEuMTA1MTQyOSwzMy4zMTc1NzE0IDMxLjIwMzUsMzMuNzM1Mjg1NyAzMS4yMDM1LDM0LjIxMDA3MTQgTDMxLjIwMzUsNDYuMDc2MDcxNCBDMzEuMjAzNSw0Ni41Nzg3ODU3IDMxLjEyNDU3MTQsNDYuOTgzMTQyOSAzMC45NjQyODU3LDQ3LjI4OTE0MjkgQzMwLjgwNCw0Ny41OTUxNDI5IDMwLjUyNzE0MjksNDcuODI5NSAzMC4xMzI1LDQ3Ljk5MjIxNDMgQzI5LjkxMDI4NTcsNDguMDg4MTQyOSAyOS42NDY3ODU3LDQ4LjE1NjE0MjkgMjkuMzM5NTcxNCw0OC4xOTYyMTQzIEMyOS4wMzExNDI5LDQ4LjIzNjI4NTcgMjguNzE3ODU3MSw0OC4yNzE1IDI4LjM5ODUsNDguMjk4MjE0MyBMMjguMzk4NSw0OS43ODU3MTQzIEw0MC4wNjUzNTcxLDQ5Ljc4NTcxNDMgTDQwLjA2NTM1NzEsNDguMjk3IEMzOS43NDQ3ODU3LDQ4LjI1NjkyODYgMzkuNDM2MzU3MSw0OC4xODg5Mjg2IDM5LjE0MTI4NTcsNDguMDkzIEMzOC44NDc0Mjg2LDQ3Ljk5ODI4NTcgMzguNTc3ODU3MSw0Ny44ODkgMzguMzMwMTQyOSw0Ny43Njc1NzE0IEwzOC4zMzAxNDI5LDQ3Ljc2NzU3MTQgWiIgaWQ9IlNoYXBlIj48L3BhdGg+CiAgICAgICAgICAgICAgICAgICAgPC9nPgogICAgICAgICAgICAgICAgPC9nPgogICAgICAgICAgICA8L2c+CiAgICAgICAgPC9nPgogICAgPC9nPgo8L3N2Zz4=",
            Question:
              "data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiIHN0YW5kYWxvbmU9Im5vIj8+Cjxzdmcgd2lkdGg9IjQwcHgiIGhlaWdodD0iNDBweCIgdmlld0JveD0iMCAwIDQwIDQwIiB2ZXJzaW9uPSIxLjEiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIgeG1sbnM6eGxpbms9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkveGxpbmsiPgogICAgPCEtLSBHZW5lcmF0b3I6IFNrZXRjaCAzLjguMyAoMjk4MDIpIC0gaHR0cDovL3d3dy5ib2hlbWlhbmNvZGluZy5jb20vc2tldGNoIC0tPgogICAgPHRpdGxlPlF1ZXN0aW9uIEljb248L3RpdGxlPgogICAgPGRlc2M+Q3JlYXRlZCB3aXRoIFNrZXRjaC48L2Rlc2M+CiAgICA8ZGVmcz48L2RlZnM+CiAgICA8ZyBpZD0iUGFnZS0xIiBzdHJva2U9Im5vbmUiIHN0cm9rZS13aWR0aD0iMSIgZmlsbD0ibm9uZSIgZmlsbC1ydWxlPSJldmVub2RkIj4KICAgICAgICA8ZyBpZD0iUXVlc3Rpb24tSWNvbiIgZmlsbD0iIzQxNzUwNSI+CiAgICAgICAgICAgIDxnIGlkPSI3MzktcXVlc3Rpb25AMngiIHRyYW5zZm9ybT0idHJhbnNsYXRlKDEuMDAwMDAwLCAxLjAwMDAwMCkiPgogICAgICAgICAgICAgICAgPGcgaWQ9IkxheWVyXzEiPgogICAgICAgICAgICAgICAgICAgIDxnIGlkPSJfeDM3XzM5LXF1ZXN0aW9uX3g0MF8yeC5wbmciPgogICAgICAgICAgICAgICAgICAgICAgICA8cGF0aCBkPSJNMjIuNDQxMDM1NywxMS4zNDYzOTI5IEMyMi4wMzM4OTI5LDEwLjk2OTEwNzEgMjEuNTU0ODIxNCwxMC42ODAwMzU3IDIxLjAwNTE3ODYsMTAuNDc5MTc4NiBDMjAuNDU0ODU3MSwxMC4yNzc2NDI5IDE5Ljg2MzE0MjksMTAuMTc3ODkyOSAxOS4yMzA3MTQzLDEwLjE3Nzg5MjkgQzE3LjkwNDEwNzEsMTAuMTc3ODkyOSAxNi43OTE5Mjg2LDEwLjU3NTUzNTcgMTUuODk1NTM1NywxMS4zNzE1IEMxNC45OTg0NjQzLDEyLjE2Njc4NTcgMTQuNDUxNTM1NywxMy4yNjMzNTcxIDE0LjI1NjEwNzEsMTQuNjYxODkyOSBMMTYuNTYxODkyOSwxNC45MDI3ODU3IEMxNi42NTI4MjE0LDE0LjA5ODY3ODYgMTYuOTI2OTY0MywxMy40NDc5Mjg2IDE3LjM4NzcxNDMsMTIuOTQ5ODU3MSBDMTcuODQ3MTA3MSwxMi40NTI0NjQzIDE4LjQ0Njk2NDMsMTIuMjAyNzUgMTkuMTg0NTcxNCwxMi4yMDI3NSBDMTkuNTE2MzkyOSwxMi4yMDI3NSAxOS44MjkyMTQzLDEyLjI2NzIxNDMgMjAuMTIzMDM1NywxMi4zOTQ3ODU3IEMyMC40MTc1MzU3LDEyLjUyMzcxNDMgMjAuNjY5OTY0MywxMi43MDAxNDI5IDIwLjg4MSwxMi45MjU0Mjg2IEMyMS4wOTIwMzU3LDEzLjE1MDAzNTcgMjEuMjYxNjc4NiwxMy40MTk0Mjg2IDIxLjM4OTI1LDEzLjczMjI1IEMyMS41MTY4MjE0LDE0LjA0NTA3MTQgMjEuNTgxMjg1NywxNC4zODc3NSAyMS41ODEyODU3LDE0Ljc1NzU3MTQgQzIxLjU4MTI4NTcsMTUuMTI3MzkyOSAyMS41MTY4MjE0LDE1LjQ2MDU3MTQgMjEuMzg5MjUsMTUuNzU3Nzg1NyBDMjEuMjYxNjc4NiwxNi4wNTUgMjEuMDk4ODIxNCwxNi4zMzY2MDcxIDIwLjkwMzM5MjksMTYuNjAxMjUgQzIwLjcwNzI4NTcsMTYuODY2NTcxNCAyMC40ODg3ODU3LDE3LjEyNDQyODYgMjAuMjQ3MjE0MywxNy4zNzI3ODU3IEMyMC4wMDYzMjE0LDE3LjYyMTgyMTQgMTkuNzY0NzUsMTcuODY3NDY0MyAxOS41MjM4NTcxLDE4LjEwODM1NzEgQzE5LjIyMjU3MTQsMTguNDEzNzE0MyAxOC45NzAxNDI5LDE4LjY3NDk2NDMgMTguNzY2NTcxNCwxOC44OTE0Mjg2IEMxOC41NjMsMTkuMTA3ODkyOSAxOC40MDA4MjE0LDE5LjMzMzE3ODYgMTguMjgwMDM1NywxOS41NjY2MDcxIEMxOC4xNTkyNSwxOS43OTkzNTcxIDE4LjA2OSwyMC4wNjA2MDcxIDE4LjAwOTI4NTcsMjAuMzQ5Njc4NiBDMTcuOTQ4ODkyOSwyMC42Mzg3NSAxNy45MTkwMzU3LDIxLjAwMDQyODYgMTcuOTE5MDM1NywyMS40MzQ3MTQzIEwxNy45MTkwMzU3LDIyLjkwNTE3ODYgTDIwLjA4OTEwNzEsMjIuOTA1MTc4NiBMMjAuMDg5MTA3MSwyMS44NDQ1NzE0IEMyMC4wODkxMDcxLDIxLjUwNzMyMTQgMjAuMTA0MDM1NywyMS4yMjYzOTI5IDIwLjEzNDU3MTQsMjEuMDAxMTA3MSBDMjAuMTY0NDI4NiwyMC43NzY1IDIwLjIyMDc1LDIwLjU3MTU3MTQgMjAuMzAzNTM1NywyMC4zODYzMjE0IEMyMC4zODYzMjE0LDIwLjIwMjQyODYgMjAuNDk5NjQyOSwyMC4wMjUzMjE0IDIwLjY0MjgyMTQsMTkuODU2MzU3MSBDMjAuNzg2LDE5LjY4NzM5MjkgMjAuOTc4MDM1NywxOS40ODI0NjQzIDIxLjIxOTYwNzEsMTkuMjQxNTcxNCBMMjEuNDQ2MjUsMTkuMDI1MTA3MSBMMjIuODAyNzE0MywxNy41MzA4OTI5IEMyMy4xMDQsMTcuMTI5MTc4NiAyMy4zMzc0Mjg2LDE2LjY5ODk2NDMgMjMuNTAzNjc4NiwxNi4yNDE2MDcxIEMyMy42NjkyNSwxNS43ODM1NzE0IDIzLjc1MjAzNTcsMTUuMjQ4ODU3MSAyMy43NTIwMzU3LDE0LjYzODgyMTQgQzIzLjc1MjAzNTcsMTMuOTMxMDcxNCAyMy42MzUzMjE0LDEzLjMgMjMuNDAxMjE0MywxMi43NDYyODU3IEMyMy4xNjg0NjQzLDEyLjE4OTg1NzEgMjIuODQ4MTc4NiwxMS43MjM2Nzg2IDIyLjQ0MTAzNTcsMTEuMzQ2MzkyOSBMMjIuNDQxMDM1NywxMS4zNDYzOTI5IFogTTE4Ljk4MTY3ODYsMjQuNjQwMjg1NyBDMTguNTc0NTM1NywyNC42NDAyODU3IDE4LjIyNDM5MjksMjQuNzk2MzU3MSAxNy45MzA1NzE0LDI1LjEwOTg1NzEgQzE3LjYzNjA3MTQsMjUuNDIzMzU3MSAxNy40ODk1LDI1Ljc5NzI1IDE3LjQ4OTUsMjYuMjMwODU3MSBDMTcuNDg5NSwyNi42NjQ0NjQzIDE3LjYzNjc1LDI3LjAzNzY3ODYgMTcuOTMwNTcxNCwyNy4zNTExNzg2IEMxOC4yMjQzOTI5LDI3LjY2NDY3ODYgMTguNTc0NTM1NywyNy44MjE0Mjg2IDE4Ljk4MTY3ODYsMjcuODIxNDI4NiBDMTkuMzg4ODIxNCwyNy44MjE0Mjg2IDE5LjczODk2NDMsMjcuNjY0Njc4NiAyMC4wMzM0NjQzLDI3LjM1MTE3ODYgQzIwLjMyNzI4NTcsMjcuMDM3Njc4NiAyMC40NzM4NTcxLDI2LjY2NDQ2NDMgMjAuNDczODU3MSwyNi4yMzA4NTcxIEMyMC40NzM4NTcxLDI1Ljc5NzI1IDIwLjMyNjYwNzEsMjUuNDIzMzU3MSAyMC4wMzM0NjQzLDI1LjEwOTg1NzEgQzE5LjczODk2NDMsMjQuNzk3MDM1NyAxOS4zODgxNDI5LDI0LjY0MDI4NTcgMTguOTgxNjc4NiwyNC42NDAyODU3IEwxOC45ODE2Nzg2LDI0LjY0MDI4NTcgWiBNMTksMCBDOC41MDY1NzE0MywwIDAsOC41MDY1NzE0MyAwLDE5IEMwLDI5LjQ5MzQyODYgOC41MDY1NzE0MywzOCAxOSwzOCBDMjkuNDkzNDI4NiwzOCAzOCwyOS40OTM0Mjg2IDM4LDE5IEMzOCw4LjUwNjU3MTQzIDI5LjQ5MzQyODYsMCAxOSwwIEwxOSwwIFogTTE5LDM2LjY0Mjg1NzEgQzkuMjU2MzkyODYsMzYuNjQyODU3MSAxLjM1NzE0Mjg2LDI4Ljc0MzYwNzEgMS4zNTcxNDI4NiwxOSBDMS4zNTcxNDI4Niw5LjI1NjM5Mjg2IDkuMjU2MzkyODYsMS4zNTcxNDI4NiAxOSwxLjM1NzE0Mjg2IEMyOC43NDM2MDcxLDEuMzU3MTQyODYgMzYuNjQyODU3MSw5LjI1NjM5Mjg2IDM2LjY0Mjg1NzEsMTkgQzM2LjY0Mjg1NzEsMjguNzQzNjA3MSAyOC43NDM2MDcxLDM2LjY0Mjg1NzEgMTksMzYuNjQyODU3MSBMMTksMzYuNjQyODU3MSBaIiBpZD0iU2hhcGUiPjwvcGF0aD4KICAgICAgICAgICAgICAgICAgICA8L2c+CiAgICAgICAgICAgICAgICA8L2c+CiAgICAgICAgICAgIDwvZz4KICAgICAgICA8L2c+CiAgICA8L2c+Cjwvc3ZnPg==",
            Success:
              "data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiIHN0YW5kYWxvbmU9Im5vIj8+Cjxzdmcgd2lkdGg9IjQwcHgiIGhlaWdodD0iNDBweCIgdmlld0JveD0iMCAwIDQwIDQwIiB2ZXJzaW9uPSIxLjEiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIgeG1sbnM6eGxpbms9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkveGxpbmsiPgogICAgPCEtLSBHZW5lcmF0b3I6IFNrZXRjaCAzLjguMyAoMjk4MDIpIC0gaHR0cDovL3d3dy5ib2hlbWlhbmNvZGluZy5jb20vc2tldGNoIC0tPgogICAgPHRpdGxlPlN1Y2Nlc3MgSWNvbjwvdGl0bGU+CiAgICA8ZGVzYz5DcmVhdGVkIHdpdGggU2tldGNoLjwvZGVzYz4KICAgIDxkZWZzPjwvZGVmcz4KICAgIDxnIGlkPSJQYWdlLTEiIHN0cm9rZT0ibm9uZSIgc3Ryb2tlLXdpZHRoPSIxIiBmaWxsPSJub25lIiBmaWxsLXJ1bGU9ImV2ZW5vZGQiPgogICAgICAgIDxnIGlkPSJTdWNjZXNzLUljb24iIGZpbGw9IiMwMDgzMDgiPgogICAgICAgICAgICA8ZyBpZD0iODg4LWNoZWNrbWFya0AyeCIgdHJhbnNmb3JtPSJ0cmFuc2xhdGUoMS4wMDAwMDAsIDEuMDAwMDAwKSI+CiAgICAgICAgICAgICAgICA8ZyBpZD0iTGF5ZXJfMSI+CiAgICAgICAgICAgICAgICAgICAgPGcgaWQ9Il94MzhfODgtY2hlY2ttYXJrX3g0MF8yeC5wbmciPgogICAgICAgICAgICAgICAgICAgICAgICA8cGF0aCBkPSJNMjcuODIxNDI4NiwxMi44OTI4NTcxIEMyNy42MzQxNDI5LDEyLjg5Mjg1NzEgMjcuNDY0NSwxMi45Njg4NTcxIDI3LjM0MTY3ODYsMTMuMDkyMzU3MSBMMTYuOTY0Mjg1NywyMy40NjkwNzE0IEwxMC42NTgzMjE0LDE3LjE2MzEwNzEgQzEwLjUzNTUsMTcuMDQwMjg1NyAxMC4zNjU4NTcxLDE2Ljk2NDI4NTcgMTAuMTc4NTcxNCwxNi45NjQyODU3IEM5LjgwNCwxNi45NjQyODU3IDkuNSwxNy4yNjgyODU3IDkuNSwxNy42NDI4NTcxIEM5LjUsMTcuODMwMTQyOSA5LjU3NiwxNy45OTk3ODU3IDkuNjk4ODIxNDMsMTguMTIyNjA3MSBMMTYuNDg0NTM1NywyNC45MDgzMjE0IEMxNi42MDczNTcxLDI1LjAzMTgyMTQgMTYuNzc3LDI1LjEwNzE0MjkgMTYuOTY0Mjg1NywyNS4xMDcxNDI5IEMxNy4xNTE1NzE0LDI1LjEwNzE0MjkgMTcuMzIxMjE0MywyNS4wMzE4MjE0IDE3LjQ0NDAzNTcsMjQuOTA4MzIxNCBMMjguMzAxMTc4NiwxNC4wNTE4NTcxIEMyOC40MjQsMTMuOTI4MzU3MSAyOC41LDEzLjc1ODcxNDMgMjguNSwxMy41NzE0Mjg2IEMyOC41LDEzLjE5NjE3ODYgMjguMTk2Njc4NiwxMi44OTI4NTcxIDI3LjgyMTQyODYsMTIuODkyODU3MSBMMjcuODIxNDI4NiwxMi44OTI4NTcxIFogTTIxLjcxNDI4NTcsMCBMMTYuMjg1NzE0MywwIEM0LjA3MTQyODU3LDAgMCw0LjA3MTQyODU3IDAsMTYuMjg1NzE0MyBMMCwyMS43MTQyODU3IEMwLDMzLjkyODU3MTQgNC4wNzE0Mjg1NywzOCAxNi4yODU3MTQzLDM4IEwyMS43MTQyODU3LDM4IEMzMy45Mjg1NzE0LDM4IDM4LDMzLjkyODU3MTQgMzgsMjEuNzE0Mjg1NyBMMzgsMTYuMjg1NzE0MyBDMzgsNC4wNzE0Mjg1NyAzMy45Mjg1NzE0LDAgMjEuNzE0Mjg1NywwIEwyMS43MTQyODU3LDAgWiBNMzYuNjQyODU3MSwyMS41MjA4OTI5IEMzNi42NDI4NTcxLDMyLjg2MjUzNTcgMzIuODYyNTM1NywzNi42NDI4NTcxIDIxLjUyMDg5MjksMzYuNjQyODU3MSBMMTYuNDc5Nzg1NywzNi42NDI4NTcxIEM1LjEzNzQ2NDI5LDM2LjY0Mjg1NzEgMS4zNTcxNDI4NiwzMi44NjI1MzU3IDEuMzU3MTQyODYsMjEuNTIwODkyOSBMMS4zNTcxNDI4NiwxNi40Nzk3ODU3IEMxLjM1NzE0Mjg2LDUuMTM3NDY0MjkgNS4xMzc0NjQyOSwxLjM1NzE0Mjg2IDE2LjQ3OTc4NTcsMS4zNTcxNDI4NiBMMjEuNTIwODkyOSwxLjM1NzE0Mjg2IEMzMi44NjI1MzU3LDEuMzU3MTQyODYgMzYuNjQyODU3MSw1LjEzNzQ2NDI5IDM2LjY0Mjg1NzEsMTYuNDc5Nzg1NyBMMzYuNjQyODU3MSwyMS41MjA4OTI5IEwzNi42NDI4NTcxLDIxLjUyMDg5MjkgWiIgaWQ9IlNoYXBlIj48L3BhdGg+CiAgICAgICAgICAgICAgICAgICAgPC9nPgogICAgICAgICAgICAgICAgPC9nPgogICAgICAgICAgICA8L2c+CiAgICAgICAgPC9nPgogICAgPC9nPgo8L3N2Zz4=",
            Warning:
              "data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiIHN0YW5kYWxvbmU9Im5vIj8+Cjxzdmcgd2lkdGg9IjQwcHgiIGhlaWdodD0iNDBweCIgdmlld0JveD0iMCAwIDQwIDQwIiB2ZXJzaW9uPSIxLjEiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIgeG1sbnM6eGxpbms9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkveGxpbmsiPgogICAgPCEtLSBHZW5lcmF0b3I6IFNrZXRjaCAzLjguMyAoMjk4MDIpIC0gaHR0cDovL3d3dy5ib2hlbWlhbmNvZGluZy5jb20vc2tldGNoIC0tPgogICAgPHRpdGxlPldhcm5pbmcgSWNvbjwvdGl0bGU+CiAgICA8ZGVzYz5DcmVhdGVkIHdpdGggU2tldGNoLjwvZGVzYz4KICAgIDxkZWZzPjwvZGVmcz4KICAgIDxnIGlkPSJQYWdlLTEiIHN0cm9rZT0ibm9uZSIgc3Ryb2tlLXdpZHRoPSIxIiBmaWxsPSJub25lIiBmaWxsLXJ1bGU9ImV2ZW5vZGQiPgogICAgICAgIDxnIGlkPSJXYXJuaW5nLUljb24iIGZpbGw9IiNGRjlEMDAiPgogICAgICAgICAgICA8ZyBpZD0iNzkxLXdhcm5pbmdAMngiIHRyYW5zZm9ybT0idHJhbnNsYXRlKDEuMDAwMDAwLCAyLjAwMDAwMCkiPgogICAgICAgICAgICAgICAgPGcgaWQ9IkxheWVyXzEiPgogICAgICAgICAgICAgICAgICAgIDxnIGlkPSJfeDM3XzkxLXdhcm5pbmdfeDQwXzJ4LnBuZyI+CiAgICAgICAgICAgICAgICAgICAgICAgIDxwYXRoIGQ9Ik0zNy44MjM1NzE0LDMzLjI3MTAzNTcgTDM3LjgzMzA3MTQsMzMuMjY1NjA3MSBMMjAuMTY5MTc4NiwwLjY1MjEwNzE0MyBMMjAuMTU3NjQyOSwwLjY1ODg5Mjg1NyBDMTkuOTIwMTQyOSwwLjI2NiAxOS40OTMzMjE0LDAgMTksMCBDMTguNTA3MzU3MSwwIDE4LjA3OTg1NzEsMC4yNjYgMTcuODQxNjc4NiwwLjY1ODg5Mjg1NyBMMTcuODMwMTQyOSwwLjY1MjEwNzE0MyBMMC4xNjY5Mjg1NzEsMzMuMjY1NjA3MSBMMC4xNzcxMDcxNDMsMzMuMjcxMDM1NyBDMC4wNjc4NTcxNDI5LDMzLjQ2NzE0MjkgMCwzMy42ODgzNTcxIDAsMzMuOTI4NTcxNCBDMCwzNC42Nzc3MTQzIDAuNjA4LDM1LjI4NTcxNDMgMS4zNTcxNDI4NiwzNS4yODU3MTQzIEwzNi42NDI4NTcxLDM1LjI4NTcxNDMgQzM3LjM5MiwzNS4yODU3MTQzIDM4LDM0LjY3NzcxNDMgMzgsMzMuOTI4NTcxNCBDMzgsMzMuNjg4MzU3MSAzNy45MzIxNDI5LDMzLjQ2NzE0MjkgMzcuODIzNTcxNCwzMy4yNzEwMzU3IEwzNy44MjM1NzE0LDMzLjI3MTAzNTcgWiBNMzUuMjg1NzE0MywzMy45Mjg1NzE0IEwzNC42MDcxNDI5LDMzLjkyODU3MTQgTDMuMzkyODU3MTQsMzMuOTI4NTcxNCBMMi43MTQyODU3MSwzMy45Mjg1NzE0IEwxLjM1NzE0Mjg2LDMzLjkyODU3MTQgTDE5LDEuMzQyODkyODYgTDM2LjY0Mjg1NzEsMzMuOTI4NTcxNCBMMzUuMjg1NzE0MywzMy45Mjg1NzE0IEwzNS4yODU3MTQzLDMzLjkyODU3MTQgWiBNMTYuMjg1NzE0MywxMy41NzE0Mjg2IEwxNy42NDI4NTcxLDIzLjA3MTQyODYgQzE3LjY0Mjg1NzEsMjMuODIwNTcxNCAxOC4yNTA4NTcxLDI0LjQyODU3MTQgMTksMjQuNDI4NTcxNCBDMTkuNzQ5MTQyOSwyNC40Mjg1NzE0IDIwLjM1NzE0MjksMjMuODIwNTcxNCAyMC4zNTcxNDI5LDIzLjA3MTQyODYgTDIxLjcxNDI4NTcsMTMuNTcxNDI4NiBDMjEuNzE0Mjg1NywxMi44MjIyODU3IDIxLjEwNjI4NTcsMTIuMjE0Mjg1NyAyMC4zNTcxNDI5LDEyLjIxNDI4NTcgTDE3LjY0Mjg1NzEsMTIuMjE0Mjg1NyBDMTYuODkzNzE0MywxMi4yMTQyODU3IDE2LjI4NTcxNDMsMTIuODIyMjg1NyAxNi4yODU3MTQzLDEzLjU3MTQyODYgTDE2LjI4NTcxNDMsMTMuNTcxNDI4NiBaIE0xOSwyMy4wNzE0Mjg2IEwxNy42NDI4NTcxLDEzLjU3MTQyODYgTDIwLjM1NzE0MjksMTMuNTcxNDI4NiBMMTksMjMuMDcxNDI4NiBMMTksMjMuMDcxNDI4NiBaIE0xOSwyNS43ODU3MTQzIEMxNy41MDEwMzU3LDI1Ljc4NTcxNDMgMTYuMjg1NzE0MywyNy4wMDEwMzU3IDE2LjI4NTcxNDMsMjguNSBDMTYuMjg1NzE0MywyOS45OTg5NjQzIDE3LjUwMTAzNTcsMzEuMjE0Mjg1NyAxOSwzMS4yMTQyODU3IEMyMC40OTg5NjQzLDMxLjIxNDI4NTcgMjEuNzE0Mjg1NywyOS45OTg5NjQzIDIxLjcxNDI4NTcsMjguNSBDMjEuNzE0Mjg1NywyNy4wMDEwMzU3IDIwLjQ5ODk2NDMsMjUuNzg1NzE0MyAxOSwyNS43ODU3MTQzIEwxOSwyNS43ODU3MTQzIFogTTE5LDI5Ljg1NzE0MjkgQzE4LjI1MDg1NzEsMjkuODU3MTQyOSAxNy42NDI4NTcxLDI5LjI0OTE0MjkgMTcuNjQyODU3MSwyOC41IEMxNy42NDI4NTcxLDI3Ljc1MDg1NzEgMTguMjUwODU3MSwyNy4xNDI4NTcxIDE5LDI3LjE0Mjg1NzEgQzE5Ljc0OTE0MjksMjcuMTQyODU3MSAyMC4zNTcxNDI5LDI3Ljc1MDg1NzEgMjAuMzU3MTQyOSwyOC41IEMyMC4zNTcxNDI5LDI5LjI0OTE0MjkgMTkuNzQ5MTQyOSwyOS44NTcxNDI5IDE5LDI5Ljg1NzE0MjkgTDE5LDI5Ljg1NzE0MjkgWiIgaWQ9IlNoYXBlIj48L3BhdGg+CiAgICAgICAgICAgICAgICAgICAgPC9nPgogICAgICAgICAgICAgICAgPC9nPgogICAgICAgICAgICA8L2c+CiAgICAgICAgPC9nPgogICAgPC9nPgo8L3N2Zz4=",
            Failed:
              "data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiIHN0YW5kYWxvbmU9Im5vIj8+Cjxzdmcgd2lkdGg9IjQwcHgiIGhlaWdodD0iNDBweCIgdmlld0JveD0iMCAwIDQwIDQwIiB2ZXJzaW9uPSIxLjEiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIgeG1sbnM6eGxpbms9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkveGxpbmsiPgogICAgPCEtLSBHZW5lcmF0b3I6IFNrZXRjaCAzLjguMyAoMjk4MDIpIC0gaHR0cDovL3d3dy5ib2hlbWlhbmNvZGluZy5jb20vc2tldGNoIC0tPgogICAgPHRpdGxlPkZhaWxlZCBJY29uPC90aXRsZT4KICAgIDxkZXNjPkNyZWF0ZWQgd2l0aCBTa2V0Y2guPC9kZXNjPgogICAgPGRlZnM+PC9kZWZzPgogICAgPGcgaWQ9IlBhZ2UtMSIgc3Ryb2tlPSJub25lIiBzdHJva2Utd2lkdGg9IjEiIGZpbGw9Im5vbmUiIGZpbGwtcnVsZT0iZXZlbm9kZCI+CiAgICAgICAgPGcgaWQ9IkZhaWxlZC1JY29uIiBmaWxsPSIjQzAwMDAwIj4KICAgICAgICAgICAgPGcgaWQ9Ijc5MS13YXJuaW5nLXNlbGVjdGVkQDJ4IiB0cmFuc2Zvcm09InRyYW5zbGF0ZSgxLjAwMDAwMCwgMi4wMDAwMDApIj4KICAgICAgICAgICAgICAgIDxnIGlkPSJMYXllcl8xIj4KICAgICAgICAgICAgICAgICAgICA8ZyBpZD0iX3gzN185MS13YXJuaW5nLXNlbGVjdGVkX3g0MF8yeC5wbmciPgogICAgICAgICAgICAgICAgICAgICAgICA8cGF0aCBkPSJNMzcuODIzNTcxNCwzMy4yNzEwMzU3IEwzNy44MzMwNzE0LDMzLjI2NTYwNzEgTDIwLjE2OTE3ODYsMC42NTIxMDcxNDMgTDIwLjE1NzY0MjksMC42NTg4OTI4NTcgQzE5LjkyMDE0MjksMC4yNjYgMTkuNDkzMzIxNCwwIDE5LDAgQzE4LjUwNzM1NzEsMCAxOC4wNzk4NTcxLDAuMjY2IDE3Ljg0MTY3ODYsMC42NTg4OTI4NTcgTDE3LjgzMDE0MjksMC42NTIxMDcxNDMgTDAuMTY2OTI4NTcxLDMzLjI2NTYwNzEgTDAuMTc3MTA3MTQzLDMzLjI3MTAzNTcgQzAuMDY3ODU3MTQyOSwzMy40NjcxNDI5IDAsMzMuNjg4MzU3MSAwLDMzLjkyODU3MTQgQzAsMzQuNjc3NzE0MyAwLjYwOCwzNS4yODU3MTQzIDEuMzU3MTQyODYsMzUuMjg1NzE0MyBMMzYuNjQyODU3MSwzNS4yODU3MTQzIEMzNy4zOTIsMzUuMjg1NzE0MyAzOCwzNC42Nzc3MTQzIDM4LDMzLjkyODU3MTQgQzM4LDMzLjY4ODM1NzEgMzcuOTMyMTQyOSwzMy40NjcxNDI5IDM3LjgyMzU3MTQsMzMuMjcxMDM1NyBMMzcuODIzNTcxNCwzMy4yNzEwMzU3IFogTTE5LDMxLjIxNDI4NTcgQzE3LjUwMTAzNTcsMzEuMjE0Mjg1NyAxNi4yODU3MTQzLDI5Ljk5ODk2NDMgMTYuMjg1NzE0MywyOC41IEMxNi4yODU3MTQzLDI3LjAwMTAzNTcgMTcuNTAxMDM1NywyNS43ODU3MTQzIDE5LDI1Ljc4NTcxNDMgQzIwLjQ5ODk2NDMsMjUuNzg1NzE0MyAyMS43MTQyODU3LDI3LjAwMTAzNTcgMjEuNzE0Mjg1NywyOC41IEMyMS43MTQyODU3LDI5Ljk5ODk2NDMgMjAuNDk4OTY0MywzMS4yMTQyODU3IDE5LDMxLjIxNDI4NTcgTDE5LDMxLjIxNDI4NTcgWiBNMjAuMzU3MTQyOSwyMy4wNzE0Mjg2IEMyMC4zNTcxNDI5LDIzLjgyMDU3MTQgMTkuNzQ5MTQyOSwyNC40Mjg1NzE0IDE5LDI0LjQyODU3MTQgQzE4LjI1MDg1NzEsMjQuNDI4NTcxNCAxNy42NDI4NTcxLDIzLjgyMDU3MTQgMTcuNjQyODU3MSwyMy4wNzE0Mjg2IEwxNi4yODU3MTQzLDEzLjU3MTQyODYgQzE2LjI4NTcxNDMsMTIuODIyMjg1NyAxNi44OTM3MTQzLDEyLjIxNDI4NTcgMTcuNjQyODU3MSwxMi4yMTQyODU3IEwyMC4zNTcxNDI5LDEyLjIxNDI4NTcgQzIxLjEwNjI4NTcsMTIuMjE0Mjg1NyAyMS43MTQyODU3LDEyLjgyMjI4NTcgMjEuNzE0Mjg1NywxMy41NzE0Mjg2IEwyMC4zNTcxNDI5LDIzLjA3MTQyODYgTDIwLjM1NzE0MjksMjMuMDcxNDI4NiBaIiBpZD0iU2hhcGUiPjwvcGF0aD4KICAgICAgICAgICAgICAgICAgICA8L2c+CiAgICAgICAgICAgICAgICA8L2c+CiAgICAgICAgICAgIDwvZz4KICAgICAgICA8L2c+CiAgICA8L2c+Cjwvc3ZnPg==",
            Deleted:
              "data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiIHN0YW5kYWxvbmU9Im5vIj8+Cjxzdmcgd2lkdGg9IjQwcHgiIGhlaWdodD0iNDBweCIgdmlld0JveD0iMCAwIDQwIDQwIiB2ZXJzaW9uPSIxLjEiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIgeG1sbnM6eGxpbms9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkveGxpbmsiPgogICAgPCEtLSBHZW5lcmF0b3I6IFNrZXRjaCAzLjguMyAoMjk4MDIpIC0gaHR0cDovL3d3dy5ib2hlbWlhbmNvZGluZy5jb20vc2tldGNoIC0tPgogICAgPHRpdGxlPlRyYXNoIEljb248L3RpdGxlPgogICAgPGRlc2M+Q3JlYXRlZCB3aXRoIFNrZXRjaC48L2Rlc2M+CiAgICA8ZGVmcz48L2RlZnM+CiAgICA8ZyBpZD0iUGFnZS0xIiBzdHJva2U9Im5vbmUiIHN0cm9rZS13aWR0aD0iMSIgZmlsbD0ibm9uZSIgZmlsbC1ydWxlPSJldmVub2RkIj4KICAgICAgICA8ZyBpZD0iVHJhc2gtSWNvbiIgZmlsbD0iIzAwMDAwMCI+CiAgICAgICAgICAgIDxnIGlkPSI3MTEtdHJhc2hAMngiIHRyYW5zZm9ybT0idHJhbnNsYXRlKDYuMDAwMDAwLCAxLjAwMDAwMCkiPgogICAgICAgICAgICAgICAgPGcgaWQ9IkxheWVyXzEiPgogICAgICAgICAgICAgICAgICAgIDxnIGlkPSJfeDM3XzExLXRyYXNoX3g0MF8yeC5wbmciPgogICAgICAgICAgICAgICAgICAgICAgICA8cGF0aCBkPSJNOC4xMTAyODU3MSw4LjE0MzUzNTcxIEM3LjczNjM5Mjg2LDguMTY1MjUgNy40NTA3MTQyOSw4LjQ4NzU3MTQzIDcuNDcyNDI4NTcsOC44NjIxNDI4NiBMOC44MjI3ODU3MSwzMy4yOTEzOTI5IEM4Ljg0NDUsMzMuNjY2NjQyOSA5LjE2NTQ2NDI5LDMzLjk1MjMyMTQgOS41NDAwMzU3MSwzMy45Mjk5Mjg2IEM5LjkxNDYwNzE0LDMzLjkwNzUzNTcgMTAuMTk5NjA3MSwzMy41ODY1NzE0IDEwLjE3Nzg5MjksMzMuMjExMzIxNCBMOC44Mjc1MzU3MSw4Ljc4MjA3MTQzIEM4LjgwNTE0Mjg2LDguNDA4MTc4NTcgOC40ODQxNzg1Nyw4LjEyMTgyMTQzIDguMTEwMjg1NzEsOC4xNDM1MzU3MSBMOC4xMTAyODU3MSw4LjE0MzUzNTcxIFogTTE0LjI1LDguMTQyODU3MTQgQzEzLjg3NTQyODYsOC4xNDI4NTcxNCAxMy41NzE0Mjg2LDguNDQ2ODU3MTQgMTMuNTcxNDI4Niw4LjgyMTQyODU3IEwxMy41NzE0Mjg2LDMzLjI1IEMxMy41NzE0Mjg2LDMzLjYyNTI1IDEzLjg3NTQyODYsMzMuOTI4NTcxNCAxNC4yNSwzMy45Mjg1NzE0IEMxNC42MjUyNSwzMy45Mjg1NzE0IDE0LjkyODU3MTQsMzMuNjI1MjUgMTQuOTI4NTcxNCwzMy4yNSBMMTQuOTI4NTcxNCw4LjgyMTQyODU3IEMxNC45Mjg1NzE0LDguNDQ2ODU3MTQgMTQuNjI1MjUsOC4xNDI4NTcxNCAxNC4yNSw4LjE0Mjg1NzE0IEwxNC4yNSw4LjE0Mjg1NzE0IFogTTI3LjgyMTQyODYsNC4wNzE0Mjg1NyBMMjAuMzU3MTQyOSw0LjA3MTQyODU3IEwyMC4zNTcxNDI5LDIuNzE0Mjg1NzEgQzIwLjM1NzE0MjksMS4yMTUzMjE0MyAxOS4xNDE4MjE0LDAgMTcuNjQyODU3MSwwIEwxMC44NTcxNDI5LDAgQzkuMzU4MTc4NTcsMCA4LjE0Mjg1NzE0LDEuMjE1MzIxNDMgOC4xNDI4NTcxNCwyLjcxNDI4NTcxIEw4LjE0Mjg1NzE0LDQuMDcxNDI4NTcgTDAuNjc4NTcxNDI5LDQuMDcxNDI4NTcgQzAuMzA0LDQuMDcxNDI4NTcgMCw0LjM3NTQyODU3IDAsNC43NSBDMCw1LjEyNTI1IDAuMzA0LDUuNDI4NTcxNDMgMC42Nzg1NzE0MjksNS40Mjg1NzE0MyBMMS4zNTcxNDI4Niw1LjQyODU3MTQzIEw0LjA3MTQyODU3LDM1LjI4NTcxNDMgQzQuMDcxNDI4NTcsMzYuNzg0Njc4NiA1LjI4Njc1LDM4IDYuNzg1NzE0MjksMzggTDIxLjcxNDI4NTcsMzggQzIzLjIxMzI1LDM4IDI0LjQyODU3MTQsMzYuNzg0Njc4NiAyNC40Mjg1NzE0LDM1LjI4NTcxNDMgTDI3LjE0Mjg1NzEsNS40Mjg1NzE0MyBMMjcuODIxNDI4Niw1LjQyODU3MTQzIEMyOC4xOTY2Nzg2LDUuNDI4NTcxNDMgMjguNSw1LjEyNTI1IDI4LjUsNC43NSBDMjguNSw0LjM3NTQyODU3IDI4LjE5NjY3ODYsNC4wNzE0Mjg1NyAyNy44MjE0Mjg2LDQuMDcxNDI4NTcgTDI3LjgyMTQyODYsNC4wNzE0Mjg1NyBaIE05LjUsMi43MTQyODU3MSBDOS41LDEuOTY1MTQyODYgMTAuMTA4LDEuMzU3MTQyODYgMTAuODU3MTQyOSwxLjM1NzE0Mjg2IEwxNy42NDI4NTcxLDEuMzU3MTQyODYgQzE4LjM5MiwxLjM1NzE0Mjg2IDE5LDEuOTY1MTQyODYgMTksMi43MTQyODU3MSBMMTksNC4wNzE0Mjg1NyBMOS41LDQuMDcxNDI4NTcgTDkuNSwyLjcxNDI4NTcxIEw5LjUsMi43MTQyODU3MSBaIE0yMy4wNzE0Mjg2LDM1LjI4NTcxNDMgQzIzLjA3MTQyODYsMzYuMDM0ODU3MSAyMi40NjM0Mjg2LDM2LjY0Mjg1NzEgMjEuNzE0Mjg1NywzNi42NDI4NTcxIEw2Ljc4NTcxNDI5LDM2LjY0Mjg1NzEgQzYuMDM2NTcxNDMsMzYuNjQyODU3MSA1LjQyODU3MTQzLDM2LjAzNDg1NzEgNS40Mjg1NzE0MywzNS4yODU3MTQzIEwyLjcxNDI4NTcxLDUuNDI4NTcxNDMgTDguMTQyODU3MTQsNS40Mjg1NzE0MyBMOS41LDUuNDI4NTcxNDMgTDE5LDUuNDI4NTcxNDMgTDIwLjM1NzE0MjksNS40Mjg1NzE0MyBMMjUuNzg1NzE0Myw1LjQyODU3MTQzIEwyMy4wNzE0Mjg2LDM1LjI4NTcxNDMgTDIzLjA3MTQyODYsMzUuMjg1NzE0MyBaIE0xOS42NzI0NjQzLDguODI0MTQyODYgTDE4LjMyMjc4NTcsMzMuMjEyNjc4NiBDMTguMzAxMDcxNCwzMy41ODcyNSAxOC41ODYwNzE0LDMzLjkwNzUzNTcgMTguOTU5OTY0MywzMy45Mjk5Mjg2IEMxOS4zMzM4NTcxLDMzLjk1MjMyMTQgMTkuNjU0ODIxNCwzMy42NjU5NjQzIDE5LjY3NzIxNDMsMzMuMjkyNzUgTDIxLjAyNzU3MTQsOC45MDM1MzU3MSBDMjEuMDQ5Mjg1Nyw4LjUyOTY0Mjg2IDIwLjc2MzYwNzEsOC4yMDg2Nzg1NyAyMC4zOTAzOTI5LDguMTg2Mjg1NzEgQzIwLjAxNTgyMTQsOC4xNjM4OTI4NiAxOS42OTQ4NTcxLDguNDQ5NTcxNDMgMTkuNjcyNDY0Myw4LjgyNDE0Mjg2IEwxOS42NzI0NjQzLDguODI0MTQyODYgWiIgaWQ9IlNoYXBlIj48L3BhdGg+CiAgICAgICAgICAgICAgICAgICAgPC9nPgogICAgICAgICAgICAgICAgPC9nPgogICAgICAgICAgICA8L2c+CiAgICAgICAgPC9nPgogICAgPC9nPgo8L3N2Zz4=",
          }),
          (e.exports = t.default);
      },
      625: (e, t, n) => {
        "use strict";
        Object.defineProperty(t, "__esModule", { value: !0 });
        var r = (function () {
            function e(e, t) {
              for (var n = 0; n < t.length; n++) {
                var r = t[n];
                (r.enumerable = r.enumerable || !1),
                  (r.configurable = !0),
                  "value" in r && (r.writable = !0),
                  Object.defineProperty(e, r.key, r);
              }
            }
            return function (t, n, r) {
              return n && e(t.prototype, n), r && e(t, r), t;
            };
          })(),
          i = a(n(929)),
          o = a(n(811)),
          s = a(n(585));
        function a(e) {
          return e && e.__esModule ? e : { default: e };
        }
        function c(e, t) {
          if (!(e instanceof t))
            throw new TypeError("Cannot call a class as a function");
        }
        function l(e, t) {
          if (!e)
            throw new ReferenceError(
              "this hasn't been initialised - super() hasn't been called"
            );
          return !t || ("object" != typeof t && "function" != typeof t) ? e : t;
        }
        var A = (function (e) {
          function t() {
            var e =
                arguments.length <= 0 || void 0 === arguments[0]
                  ? ""
                  : arguments[0],
              n =
                arguments.length <= 1 || void 0 === arguments[1]
                  ? ""
                  : arguments[1];
            c(this, t);
            var r = l(this, Object.getPrototypeOf(t).call(this));
            return (
              (r.elems = {}),
              (r.title = n),
              (r.text = e),
              (r.buttons = []),
              (r.textFields = []),
              (r.result = !1),
              (r.iconURL = null),
              (r.cancelable = !0),
              (r.cancelled = !1),
              (r.dismissed = !1),
              r
            );
          }
          return (
            (function (e, t) {
              if ("function" != typeof t && null !== t)
                throw new TypeError(
                  "Super expression must either be null or a function, not " +
                    typeof t
                );
              (e.prototype = Object.create(t && t.prototype, {
                constructor: {
                  value: e,
                  enumerable: !1,
                  writable: !0,
                  configurable: !0,
                },
              })),
                t &&
                  (Object.setPrototypeOf
                    ? Object.setPrototypeOf(e, t)
                    : (e.__proto__ = t));
            })(t, e),
            r(t, null, [
              {
                key: "alert",
                value: function (e, n, r) {
                  var i =
                    arguments.length <= 3 || void 0 === arguments[3]
                      ? "Close"
                      : arguments[3];
                  if ("undefined" == typeof window)
                    return Promise.resolve(console.log("Alert: " + e));
                  var o = new t(e, n);
                  return (
                    o.addButton(i, null),
                    !1 !== r && o.setIcon(r || t.Icons.Information),
                    o.show()
                  );
                },
              },
              {
                key: "confirm",
                value: function (e, n, r) {
                  var i =
                      arguments.length <= 3 || void 0 === arguments[3]
                        ? "OK"
                        : arguments[3],
                    o =
                      arguments.length <= 4 || void 0 === arguments[4]
                        ? "Cancel"
                        : arguments[4];
                  if ("undefined" == typeof window)
                    return Promise.resolve(console.log("Alert: " + e));
                  var s = new t(e, n);
                  return (
                    s.addButton(i, !0),
                    s.addButton(o, !1),
                    !1 !== r && s.setIcon(r || t.Icons.Question),
                    s.show()
                  );
                },
              },
              {
                key: "prompt",
                value: function (e, n, r, i, o) {
                  var s =
                      arguments.length <= 5 || void 0 === arguments[5]
                        ? "OK"
                        : arguments[5],
                    a =
                      arguments.length <= 6 || void 0 === arguments[6]
                        ? "Cancel"
                        : arguments[6];
                  if ("undefined" == typeof window)
                    return Promise.resolve(console.log("Alert: " + e));
                  var c = new t(e, i);
                  return (
                    c.addButton(s, !0, "default"),
                    c.addButton(a, !1, "cancel"),
                    !1 !== o && c.setIcon(o || t.Icons.Question),
                    c.addTextField(n, null, r),
                    c.show().then(function (e) {
                      return c.cancelled ? null : c.getTextFieldValue(0);
                    })
                  );
                },
              },
              {
                key: "loader",
                value: function (e, n) {
                  if ("undefined" == typeof window)
                    return Promise.resolve(console.log("Loading: " + e));
                  var r = new t(e);
                  return (r.cancelable = n), r.show();
                },
              },
            ]),
            r(t, [
              {
                key: "setIcon",
                value: function (e) {
                  this.iconURL = e;
                },
              },
              {
                key: "addButton",
                value: function (e, t, n) {
                  var r = this;
                  return new Promise(function (i, o) {
                    r.buttons.push({
                      text: e,
                      value: void 0 === t ? e : t,
                      type: n || (0 == r.buttons.length ? "default" : "normal"),
                      callback: i,
                    });
                  });
                },
              },
              {
                key: "addTextField",
                value: function (e, t, n) {
                  this.textFields.push({
                    value: e || "",
                    type: t || "text",
                    placeholder: n || "",
                  });
                },
              },
              {
                key: "getTextFieldValue",
                value: function (e) {
                  var t = this.textFields[e];
                  return t.elem ? t.elem.value : t.value;
                },
              },
              {
                key: "show",
                value: function () {
                  var e = this;
                  return (
                    t.popupQueue.add(this).then(function () {
                      e._show(), e.emit("opened");
                    }),
                    this
                  );
                },
              },
              {
                key: "then",
                value: function (e) {
                  return this.when("closed").then(e);
                },
              },
              {
                key: "dismiss",
                value: function (e) {
                  if (!this.dismissed)
                    return (
                      (this.dismissed = !0),
                      t.popupQueue.remove(this),
                      (this.result = e),
                      void 0 === e && (this.cancelled = !0),
                      this.removeElements(),
                      window.removeEventListener("keydown", this),
                      this.cancelled
                        ? this.emit("cancelled", this.result)
                        : this.emit("complete", this.result),
                      this.emit("closed", this.result),
                      this
                    );
                },
              },
              {
                key: "dismissIn",
                value: function (e) {
                  return setTimeout(this.dismiss.bind(this), e), this;
                },
              },
              {
                key: "_show",
                value: function () {
                  this.createBackground(),
                    this.createPopup(),
                    window.addEventListener("keydown", this);
                },
              },
              {
                key: "createBackground",
                value: function () {
                  var e = this;
                  (this.elems.background = document.createElement("div")),
                    (this.elems.background.style.cssText =
                      "position: fixed; top: 0px; left: 0px; width: 100%; height: 100%; z-index: 10000; background-color: rgba(0, 0, 0, 0.1); opacity: 0; transition: opacity 0.15s; "),
                    document.body.appendChild(this.elems.background),
                    setTimeout(function () {
                      e.elems.background.offsetWidth,
                        (e.elems.background.style.opacity = 1);
                    }, 0);
                },
              },
              {
                key: "createPopup",
                value: function () {
                  var e = this;
                  (this.elems.container = document.createElement("div")),
                    (this.elems.container.focusable = !0),
                    (this.elems.container.style.cssText =
                      "position: fixed; top: 0px; left: 0px; width: 100%; height: 100%; z-index: 10001; display: flex; justify-content: center; align-items: center; opacity: 0; transform: translateY(-40px); transition: opacity 0.15s, transform 0.15s; "),
                    document.body.appendChild(this.elems.container),
                    setTimeout(function () {
                      e.elems.container.offsetWidth,
                        (e.elems.container.style.opacity = 1),
                        (e.elems.container.style.transform = "translateY(0px)");
                    }, 0),
                    this.addTouchHandler(this.elems.container, function () {
                      e.cancelable && ((e.cancelled = !0), e.dismiss());
                    }),
                    (this.elems.window = document.createElement("div")),
                    (this.elems.window.style.cssText =
                      "position: relative; background-color: rgba(255, 255, 255, 0.95); box-shadow: 0px 0px 20px rgba(0, 0, 0, 0.25); border-radius: 5px; padding: 10px; min-width: 50px; min-height: 10px; max-width: 50%; max-height: 90%; backdrop-filter: blur(8px); -webkit-backdrop-filter: blur(8px); "),
                    this.elems.container.appendChild(this.elems.window),
                    this.iconURL &&
                      ((this.elems.icon = document.createElement("img")),
                      (this.elems.icon.style.cssText =
                        "display: block; margin: auto; max-height: 40px; text-align: center; font-family: Helvetica, Arial; font-size: 17px; font-weight: bold; color: #000; cursor: default; padding: 10px 0px; "),
                      (this.elems.icon.src = this.iconURL),
                      this.elems.window.appendChild(this.elems.icon)),
                    this.title &&
                      ((this.elems.title = document.createElement("div")),
                      (this.elems.title.style.cssText =
                        "display: block; text-align: center; font-family: Helvetica, Arial; font-size: 17px; font-weight: bold; color: #000; cursor: default; padding: 2px 20px; "),
                      (this.elems.title.innerHTML = this.title),
                      this.elems.window.appendChild(this.elems.title)),
                    this.text &&
                      ((this.elems.text = document.createElement("div")),
                      (this.elems.text.style.cssText =
                        "display: block; text-align: center; font-family: Helvetica, Arial; font-size: 15px; font-weight: normal; color: #000; cursor: default; padding: 2px 20px; "),
                      (this.elems.text.innerHTML = this.text),
                      this.elems.window.appendChild(this.elems.text)),
                    this.textFields.length > 0 &&
                      ((this.elems.textFields = document.createElement("div")),
                      (this.elems.textFields.style.cssText =
                        "display: block; "),
                      this.elems.window.appendChild(this.elems.textFields),
                      this.textFields.forEach(function (t, n) {
                        (t.elem = document.createElement("input")),
                          (t.elem.style.cssText =
                            "display: block; width: 90%; min-width: 250px; padding: 5px 0px; margin: 10px auto; background-color: #FFF; border: 1px solid #EEE; border-radius: 5px; text-align: center; font-family: Helvetica, Arial; font-size: 15px; color: #222; "),
                          (t.elem.value = t.value),
                          (t.elem.placeholder = t.placeholder),
                          (t.elem.type = t.type),
                          e.elems.textFields.appendChild(t.elem),
                          t.elem.addEventListener("keypress", function (t) {
                            13 == t.keyCode &&
                              (n + 1 >= e.textFields.length
                                ? e.dismiss("enter-pressed")
                                : e.textFields[n + 1].elem.focus());
                          });
                      }),
                      this.textFields[0].elem.focus()),
                    this.buttons.length > 0 &&
                      ((this.elems.buttons = document.createElement("div")),
                      (this.elems.buttons.style.cssText =
                        "display: block; display: flex; justify-content: space-around; align-items: center; text-align: right; border-top: 1px solid #EEE; margin-top: 10px; "),
                      this.elems.window.appendChild(this.elems.buttons),
                      this.buttons.forEach(function (t) {
                        var n = document.createElement("div");
                        (n.style.cssText =
                          "display: inline-block; font-family: Helvetica, Arial; font-size: 15px; font-weight: 200; color: #08F; padding: 10px 20px; padding-bottom: 0px; cursor: pointer; "),
                          (n.innerText = t.text),
                          e.elems.buttons.appendChild(n),
                          e.addTouchHandler(n, function () {
                            t.callback && t.callback(t.value),
                              "cancel" == t.type && (e.cancelled = !0),
                              e.dismiss(t.value);
                          });
                      }));
                },
              },
              {
                key: "removeElements",
                value: function () {
                  var e = this;
                  this.elems &&
                    this.elems.container &&
                    ((this.elems.background.style.opacity = 0),
                    (this.elems.container.style.opacity = 0),
                    (this.elems.container.style.transform = "translateY(40px)"),
                    setTimeout(function () {
                      e.removeElement(e.elems.background),
                        e.removeElement(e.elems.container);
                    }, 250));
                },
              },
              {
                key: "removeElement",
                value: function (e) {
                  e && e.parentNode && e.parentNode.removeChild(e);
                },
              },
              {
                key: "addTouchHandler",
                value: function (e, t) {
                  var n = function (n) {
                    "input" != n.target.nodeName.toLowerCase() &&
                      n.preventDefault(),
                      n.target == e && t();
                  };
                  this.elems.container.addEventListener("mousedown", n, !0),
                    this.elems.container.addEventListener("touchstart", n, !0);
                },
              },
              {
                key: "handleEvent",
                value: function (e) {
                  if (13 == e.keyCode) {
                    for (var t = 0; t < this.buttons.length; t++)
                      if ("default" == this.buttons[t].type)
                        return (
                          this.dismiss(this.buttons[t].value),
                          e.preventDefault(),
                          void (
                            this.buttons[t].callback &&
                            this.buttons[t].callback(this.result)
                          )
                        );
                    return (this.cancelled = !0), void this.dismiss();
                  }
                  if (27 == e.keyCode) {
                    if (!this.cancelable) return;
                    for (
                      this.cancelled = !0, this.result = null, t = 0;
                      t < this.buttons.length;
                      t++
                    )
                      if ("cancel" == this.buttons[t].type)
                        return (
                          this.dismiss(this.buttons[t].value),
                          e.preventDefault(),
                          void (
                            this.buttons[t].callback &&
                            this.buttons[t].callback(this.result)
                          )
                        );
                    return (this.cancelled = !0), void this.dismiss();
                  }
                },
              },
            ]),
            t
          );
        })(o.default);
        (t.default = A),
          (A.Icons = s.default),
          (A.popupQueue = new i.default()),
          (A.Queue = i.default),
          (A.EventSource = o.default),
          (e.exports = t.default);
      },
      929: (e, t, n) => {
        "use strict";
        Object.defineProperty(t, "__esModule", { value: !0 });
        var r,
          i = (function () {
            function e(e, t) {
              for (var n = 0; n < t.length; n++) {
                var r = t[n];
                (r.enumerable = r.enumerable || !1),
                  (r.configurable = !0),
                  "value" in r && (r.writable = !0),
                  Object.defineProperty(e, r.key, r);
              }
            }
            return function (t, n, r) {
              return n && e(t.prototype, n), r && e(t, r), t;
            };
          })(),
          o = (function (e) {
            function t() {
              !(function (e, t) {
                if (!(e instanceof t))
                  throw new TypeError("Cannot call a class as a function");
              })(this, t);
              var e = (function (e, t) {
                if (!e)
                  throw new ReferenceError(
                    "this hasn't been initialised - super() hasn't been called"
                  );
                return !t || ("object" != typeof t && "function" != typeof t)
                  ? e
                  : t;
              })(this, Object.getPrototypeOf(t).call(this));
              return (e.items = []), (e.current = null), e;
            }
            return (
              (function (e, t) {
                if ("function" != typeof t && null !== t)
                  throw new TypeError(
                    "Super expression must either be null or a function, not " +
                      typeof t
                  );
                (e.prototype = Object.create(t && t.prototype, {
                  constructor: {
                    value: e,
                    enumerable: !1,
                    writable: !0,
                    configurable: !0,
                  },
                })),
                  t &&
                    (Object.setPrototypeOf
                      ? Object.setPrototypeOf(e, t)
                      : (e.__proto__ = t));
              })(t, e),
              i(t, [
                {
                  key: "add",
                  value: function (e) {
                    var t = this;
                    return new Promise(function (n, r) {
                      t.items.push({ item: e, activateHandler: n }),
                        t.emit("added", e),
                        setTimeout(t.checkActivated.bind(t), 1);
                    });
                  },
                },
                {
                  key: "checkActivated",
                  value: function () {
                    if (!this.current)
                      if (0 != this.items.length) {
                        this.current = this.items[0];
                        var e = { item: this.current.item };
                        this.current.activateHandler &&
                          this.current.activateHandler(e),
                          this.emit("activated", e);
                      } else this.emit("empty");
                  },
                },
                {
                  key: "remove",
                  value: function (e) {
                    for (var t = 0; t < this.items.length; t++)
                      this.items[t].item == e && this.items.splice(t--, 1);
                    this.emit("removed", e),
                      this.current &&
                        this.current.item == e &&
                        (this.current = null),
                      setTimeout(this.checkActivated.bind(this), 1);
                  },
                },
              ]),
              t
            );
          })(((r = n(811)) && r.__esModule ? r : { default: r }).default);
        (t.default = o), (e.exports = t.default);
      },
      379: (e) => {
        "use strict";
        var t = [];
        function n(e) {
          for (var n = -1, r = 0; r < t.length; r++)
            if (t[r].identifier === e) {
              n = r;
              break;
            }
          return n;
        }
        function r(e, r) {
          for (var o = {}, s = [], a = 0; a < e.length; a++) {
            var c = e[a],
              l = r.base ? c[0] + r.base : c[0],
              A = o[l] || 0,
              d = "".concat(l, " ").concat(A);
            o[l] = A + 1;
            var u = n(d),
              h = {
                css: c[1],
                media: c[2],
                sourceMap: c[3],
                supports: c[4],
                layer: c[5],
              };
            if (-1 !== u) t[u].references++, t[u].updater(h);
            else {
              var g = i(h, r);
              (r.byIndex = a),
                t.splice(a, 0, { identifier: d, updater: g, references: 1 });
            }
            s.push(d);
          }
          return s;
        }
        function i(e, t) {
          var n = t.domAPI(t);
          return (
            n.update(e),
            function (t) {
              if (t) {
                if (
                  t.css === e.css &&
                  t.media === e.media &&
                  t.sourceMap === e.sourceMap &&
                  t.supports === e.supports &&
                  t.layer === e.layer
                )
                  return;
                n.update((e = t));
              } else n.remove();
            }
          );
        }
        e.exports = function (e, i) {
          var o = r((e = e || []), (i = i || {}));
          return function (e) {
            e = e || [];
            for (var s = 0; s < o.length; s++) {
              var a = n(o[s]);
              t[a].references--;
            }
            for (var c = r(e, i), l = 0; l < o.length; l++) {
              var A = n(o[l]);
              0 === t[A].references && (t[A].updater(), t.splice(A, 1));
            }
            o = c;
          };
        };
      },
      569: (e) => {
        "use strict";
        var t = {};
        e.exports = function (e, n) {
          var r = (function (e) {
            if (void 0 === t[e]) {
              var n = document.querySelector(e);
              if (
                window.HTMLIFrameElement &&
                n instanceof window.HTMLIFrameElement
              )
                try {
                  n = n.contentDocument.head;
                } catch (e) {
                  n = null;
                }
              t[e] = n;
            }
            return t[e];
          })(e);
          if (!r)
            throw new Error(
              "Couldn't find a style target. This probably means that the value for the 'insert' parameter is invalid."
            );
          r.appendChild(n);
        };
      },
      216: (e) => {
        "use strict";
        e.exports = function (e) {
          var t = document.createElement("style");
          return e.setAttributes(t, e.attributes), e.insert(t, e.options), t;
        };
      },
      565: (e, t, n) => {
        "use strict";
        e.exports = function (e) {
          var t = n.nc;
          t && e.setAttribute("nonce", t);
        };
      },
      795: (e) => {
        "use strict";
        e.exports = function (e) {
          var t = e.insertStyleElement(e);
          return {
            update: function (n) {
              !(function (e, t, n) {
                var r = "";
                n.supports && (r += "@supports (".concat(n.supports, ") {")),
                  n.media && (r += "@media ".concat(n.media, " {"));
                var i = void 0 !== n.layer;
                i &&
                  (r += "@layer".concat(
                    n.layer.length > 0 ? " ".concat(n.layer) : "",
                    " {"
                  )),
                  (r += n.css),
                  i && (r += "}"),
                  n.media && (r += "}"),
                  n.supports && (r += "}");
                var o = n.sourceMap;
                o &&
                  "undefined" != typeof btoa &&
                  (r +=
                    "\n/*# sourceMappingURL=data:application/json;base64,".concat(
                      btoa(unescape(encodeURIComponent(JSON.stringify(o)))),
                      " */"
                    )),
                  t.styleTagTransform(r, e, t.options);
              })(t, e, n);
            },
            remove: function () {
              !(function (e) {
                if (null === e.parentNode) return !1;
                e.parentNode.removeChild(e);
              })(t);
            },
          };
        };
      },
      589: (e) => {
        "use strict";
        e.exports = function (e, t) {
          if (t.styleSheet) t.styleSheet.cssText = e;
          else {
            for (; t.firstChild; ) t.removeChild(t.firstChild);
            t.appendChild(document.createTextNode(e));
          }
        };
      },
      840: (e, t, n) => {
        var r;
        if ("object" == typeof globalThis) r = globalThis;
        else
          try {
            r = n(284);
          } catch (e) {
          } finally {
            if ((r || "undefined" == typeof window || (r = window), !r))
              throw new Error("Could not determine global this");
          }
        var i = r.WebSocket || r.MozWebSocket,
          o = n(387);
        function s(e, t) {
          return t ? new i(e, t) : new i(e);
        }
        i &&
          ["CONNECTING", "OPEN", "CLOSING", "CLOSED"].forEach(function (e) {
            Object.defineProperty(s, e, {
              get: function () {
                return i[e];
              },
            });
          }),
          (e.exports = { w3cwebsocket: i ? s : null, version: o });
      },
      387: (e, t, n) => {
        e.exports = n(794).version;
      },
      601: (e) => {
        "use strict";
        e.exports =
          "data:image/svg+xml,%3csvg viewBox=%270 0 16 16%27 fill=%27white%27 xmlns=%27http://www.w3.org/2000/svg%27%3e%3ccircle cx=%278%27 cy=%278%27 r=%273%27/%3e%3c/svg%3e";
      },
      133: (e) => {
        "use strict";
        e.exports =
          "data:image/svg+xml,%3csvg viewBox=%270 0 16 16%27 fill=%27white%27 xmlns=%27http://www.w3.org/2000/svg%27%3e%3cpath d=%27M12.207 4.793a1 1 0 010 1.414l-5 5a1 1 0 01-1.414 0l-2-2a1 1 0 011.414-1.414L6.5 9.086l4.293-4.293a1 1 0 011.414 0z%27/%3e%3c/svg%3e";
      },
      686: (e) => {
        "use strict";
        e.exports =
          "data:image/svg+xml,%3csvg xmlns=%27http://www.w3.org/2000/svg%27 fill=%27none%27 viewBox=%270 0 16 16%27%3e%3cpath stroke=%27white%27 stroke-linecap=%27round%27 stroke-linejoin=%27round%27 stroke-width=%272%27 d=%27M4 8h8%27/%3e%3c/svg%3e";
      },
      909: (e) => {
        "use strict";
        e.exports =
          "data:image/svg+xml,%3csvg xmlns=%27http://www.w3.org/2000/svg%27 fill=%27none%27 viewBox=%270 0 20 20%27%3e%3cpath stroke=%27%236b7280%27 stroke-linecap=%27round%27 stroke-linejoin=%27round%27 stroke-width=%271.5%27 d=%27M6 8l4 4 4-4%27/%3e%3c/svg%3e";
      },
      794: (e) => {
        "use strict";
        e.exports = { version: "1.0.34" };
      },
    },
    o = {};
  function s(e) {
    var t = o[e];
    if (void 0 !== t) return t.exports;
    var n = (o[e] = { id: e, exports: {} });
    return i[e].call(n.exports, n, n.exports, s), n.exports;
  }
  (s.m = i),
    (s.n = (e) => {
      var t = e && e.__esModule ? () => e.default : () => e;
      return s.d(t, { a: t }), t;
    }),
    (t = Object.getPrototypeOf
      ? (e) => Object.getPrototypeOf(e)
      : (e) => e.__proto__),
    (s.t = function (n, r) {
      if ((1 & r && (n = this(n)), 8 & r)) return n;
      if ("object" == typeof n && n) {
        if (4 & r && n.__esModule) return n;
        if (16 & r && "function" == typeof n.then) return n;
      }
      var i = Object.create(null);
      s.r(i);
      var o = {};
      e = e || [null, t({}), t([]), t(t)];
      for (var a = 2 & r && n; "object" == typeof a && !~e.indexOf(a); a = t(a))
        Object.getOwnPropertyNames(a).forEach((e) => (o[e] = () => n[e]));
      return (o.default = () => n), s.d(i, o), i;
    }),
    (s.d = (e, t) => {
      for (var n in t)
        s.o(t, n) &&
          !s.o(e, n) &&
          Object.defineProperty(e, n, { enumerable: !0, get: t[n] });
    }),
    (s.f = {}),
    (s.e = (e) =>
      Promise.all(Object.keys(s.f).reduce((t, n) => (s.f[n](e, t), t), []))),
    (s.u = (e) => e + ".js"),
    (s.g = (function () {
      if ("object" == typeof globalThis) return globalThis;
      try {
        return this || new Function("return this")();
      } catch (e) {
        if ("object" == typeof window) return window;
      }
    })()),
    (s.o = (e, t) => Object.prototype.hasOwnProperty.call(e, t)),
    (n = {}),
    (r = "tts:"),
    (s.l = (e, t, i, o) => {
      if (n[e]) n[e].push(t);
      else {
        var a, c;
        if (void 0 !== i)
          for (
            var l = document.getElementsByTagName("script"), A = 0;
            A < l.length;
            A++
          ) {
            var d = l[A];
            if (
              d.getAttribute("src") == e ||
              d.getAttribute("data-webpack") == r + i
            ) {
              a = d;
              break;
            }
          }
        a ||
          ((c = !0),
          ((a = document.createElement("script")).charset = "utf-8"),
          (a.timeout = 120),
          s.nc && a.setAttribute("nonce", s.nc),
          a.setAttribute("data-webpack", r + i),
          (a.src = e)),
          (n[e] = [t]);
        var u = (t, r) => {
            (a.onerror = a.onload = null), clearTimeout(h);
            var i = n[e];
            if (
              (delete n[e],
              a.parentNode && a.parentNode.removeChild(a),
              i && i.forEach((e) => e(r)),
              t)
            )
              return t(r);
          },
          h = setTimeout(
            u.bind(null, void 0, { type: "timeout", target: a }),
            12e4
          );
        (a.onerror = u.bind(null, a.onerror)),
          (a.onload = u.bind(null, a.onload)),
          c && document.head.appendChild(a);
      }
    }),
    (s.r = (e) => {
      "undefined" != typeof Symbol &&
        Symbol.toStringTag &&
        Object.defineProperty(e, Symbol.toStringTag, { value: "Module" }),
        Object.defineProperty(e, "__esModule", { value: !0 });
    }),
    (() => {
      var e;
      s.g.importScripts && (e = s.g.location + "");
      var t = s.g.document;
      if (!e && t && (t.currentScript && (e = t.currentScript.src), !e)) {
        var n = t.getElementsByTagName("script");
        n.length && (e = n[n.length - 1].src);
      }
      if (!e)
        throw new Error(
          "Automatic publicPath is not supported in this browser"
        );
      (e = e
        .replace(/#.*$/, "")
        .replace(/\?.*$/, "")
        .replace(/\/[^\/]+$/, "/")),
        (s.p = e);
    })(),
    (() => {
      s.b = document.baseURI || self.location.href;
      var e = { 680: 0, 98: 0 };
      s.f.j = (t, n) => {
        var r = s.o(e, t) ? e[t] : void 0;
        if (0 !== r)
          if (r) n.push(r[2]);
          else {
            var i = new Promise((n, i) => (r = e[t] = [n, i]));
            n.push((r[2] = i));
            var o = s.p + s.u(t),
              a = new Error();
            s.l(
              o,
              (n) => {
                if (s.o(e, t) && (0 !== (r = e[t]) && (e[t] = void 0), r)) {
                  var i = n && ("load" === n.type ? "missing" : n.type),
                    o = n && n.target && n.target.src;
                  (a.message =
                    "Loading chunk " + t + " failed.\n(" + i + ": " + o + ")"),
                    (a.name = "ChunkLoadError"),
                    (a.type = i),
                    (a.request = o),
                    r[1](a);
                }
              },
              "chunk-" + t,
              t
            );
          }
      };
      var t = (t, n) => {
          var r,
            i,
            [o, a, c] = n,
            l = 0;
          if (o.some((t) => 0 !== e[t])) {
            for (r in a) s.o(a, r) && (s.m[r] = a[r]);
            c && c(s);
          }
          for (t && t(n); l < o.length; l++)
            (i = o[l]), s.o(e, i) && e[i] && e[i][0](), (e[i] = 0);
        },
        n = (self.webpackChunktts = self.webpackChunktts || []);
      n.forEach(t.bind(null, 0)), (n.push = t.bind(null, n.push.bind(n)));
    })(),
    (s.nc = void 0),
    (() => {
      "use strict";
      s(514);
      var e = s(98);
      class t {
        constructor(e) {
          this.client = e;
        }
        static flatten(e, t = "") {
          let n = {};
          for (const r in e) {
            let i = e[r],
              o = t ? `${t}[${r}]` : r;
            Array.isArray(i)
              ? (n = Object.assign(n, this.flatten(i, o)))
              : (n[o] = i);
          }
          return n;
        }
      }
      t.CHUNK_SIZE = 5242880;
      class n {}
      (n.equal = (e, t) => n.addQuery(e, "equal", t)),
        (n.notEqual = (e, t) => n.addQuery(e, "notEqual", t)),
        (n.lesser = (e, t) => n.addQuery(e, "lesser", t)),
        (n.lesserEqual = (e, t) => n.addQuery(e, "lesserEqual", t)),
        (n.greater = (e, t) => n.addQuery(e, "greater", t)),
        (n.greaterEqual = (e, t) => n.addQuery(e, "greaterEqual", t)),
        (n.search = (e, t) => n.addQuery(e, "search", t)),
        (n.addQuery = (e, t, r) =>
          r instanceof Array
            ? `${e}.${t}(${r.map((e) => n.parseValues(e)).join(",")})`
            : `${e}.${t}(${n.parseValues(r)})`),
        (n.parseValues = (e) =>
          "string" == typeof e || e instanceof String ? `"${e}"` : `${e}`);
      class r extends Error {
        constructor(e, t = 0, n = "", r = "") {
          super(e),
            (this.name = "AppwriteException"),
            (this.message = e),
            (this.code = t),
            (this.type = n),
            (this.response = r);
        }
      }
      var i = s(379),
        o = s.n(i),
        a = s(795),
        c = s.n(a),
        l = s(569),
        A = s.n(l),
        d = s(565),
        u = s.n(d),
        h = s(216),
        g = s.n(h),
        p = s(589),
        m = s.n(p),
        w = s(265),
        E = {};
      (E.styleTagTransform = m()),
        (E.setAttributes = u()),
        (E.insert = A().bind(null, "head")),
        (E.domAPI = c()),
        (E.insertStyleElement = g()),
        o()(w.Z, E),
        w.Z && w.Z.locals && w.Z.locals;
      var f = s(625),
        y = s.n(f);
      const b = { "X-Client-Info": "supabase-js/1.35.6" },
        C = "Request Failed",
        M = "supabase.auth.token",
        B = {
          name: "sb",
          lifetime: 28800,
          domain: "",
          path: "/",
          sameSite: "lax",
        };
      var v = function (e, t, n, r) {
        return new (n || (n = Promise))(function (i, o) {
          function s(e) {
            try {
              c(r.next(e));
            } catch (e) {
              o(e);
            }
          }
          function a(e) {
            try {
              c(r.throw(e));
            } catch (e) {
              o(e);
            }
          }
          function c(e) {
            var t;
            e.done
              ? i(e.value)
              : ((t = e.value),
                t instanceof n
                  ? t
                  : new n(function (e) {
                      e(t);
                    })).then(s, a);
          }
          c((r = r.apply(e, t || [])).next());
        });
      };
      const x = (e) =>
        e.msg ||
        e.message ||
        e.error_description ||
        e.error ||
        JSON.stringify(e);
      function N(e, t, n, r, i) {
        return v(this, void 0, void 0, function* () {
          return new Promise((o, s) => {
            e(
              n,
              ((e, t, n) => {
                const r = {
                  method: e,
                  headers: (null == t ? void 0 : t.headers) || {},
                };
                return (
                  "GET" === e ||
                    ((r.headers = Object.assign(
                      { "Content-Type": "text/plain;charset=UTF-8" },
                      null == t ? void 0 : t.headers
                    )),
                    (r.body = JSON.stringify(n))),
                  r
                );
              })(t, r, i)
            )
              .then((e) => {
                if (!e.ok) throw e;
                return (null == r ? void 0 : r.noResolveJson) ? o : e.json();
              })
              .then((e) => o(e))
              .catch((e) =>
                ((e, t) =>
                  (null == e ? void 0 : e.status)
                    ? "function" != typeof e.json
                      ? t(e)
                      : void e
                          .json()
                          .then((n) =>
                            t({
                              message: x(n),
                              status: (null == e ? void 0 : e.status) || 500,
                            })
                          )
                    : t({ message: C }))(e, s)
              );
          });
        });
      }
      function I(e, t, n) {
        return v(this, void 0, void 0, function* () {
          return N(e, "GET", t, n);
        });
      }
      function D(e, t, n, r) {
        return v(this, void 0, void 0, function* () {
          return N(e, "POST", t, r, n);
        });
      }
      function j(e, t, n, r) {
        return v(this, void 0, void 0, function* () {
          return N(e, "PUT", t, r, n);
        });
      }
      function k(e, t, n) {
        const r = n.map((t) => {
            return (
              (n = t),
              (r = (function (e) {
                if (!e || !e.headers || !e.headers.host)
                  throw new Error('The "host" request header is not available');
                const t =
                  (e.headers.host.indexOf(":") > -1 &&
                    e.headers.host.split(":")[0]) ||
                  e.headers.host;
                return !(
                  ["localhost", "127.0.0.1"].indexOf(t) > -1 ||
                  t.endsWith(".local")
                );
              })(e)),
              (function (e, t, n) {
                const r = n || {},
                  i = encodeURIComponent,
                  o = /^[\u0009\u0020-\u007e\u0080-\u00ff]+$/;
                if ("function" != typeof i)
                  throw new TypeError("option encode is invalid");
                if (!o.test(e)) throw new TypeError("argument name is invalid");
                const s = i(t);
                if (s && !o.test(s))
                  throw new TypeError("argument val is invalid");
                let a = e + "=" + s;
                if (null != r.maxAge) {
                  const e = r.maxAge - 0;
                  if (isNaN(e) || !isFinite(e))
                    throw new TypeError("option maxAge is invalid");
                  a += "; Max-Age=" + Math.floor(e);
                }
                if (r.domain) {
                  if (!o.test(r.domain))
                    throw new TypeError("option domain is invalid");
                  a += "; Domain=" + r.domain;
                }
                if (r.path) {
                  if (!o.test(r.path))
                    throw new TypeError("option path is invalid");
                  a += "; Path=" + r.path;
                }
                if (r.expires) {
                  if ("function" != typeof r.expires.toUTCString)
                    throw new TypeError("option expires is invalid");
                  a += "; Expires=" + r.expires.toUTCString();
                }
                if (
                  (r.httpOnly && (a += "; HttpOnly"),
                  r.secure && (a += "; Secure"),
                  r.sameSite)
                )
                  switch (
                    "string" == typeof r.sameSite
                      ? r.sameSite.toLowerCase()
                      : r.sameSite
                  ) {
                    case "lax":
                      a += "; SameSite=Lax";
                      break;
                    case "strict":
                      a += "; SameSite=Strict";
                      break;
                    case "none":
                      a += "; SameSite=None";
                      break;
                    default:
                      throw new TypeError("option sameSite is invalid");
                  }
                return a;
              })(n.name, n.value, {
                maxAge: n.maxAge,
                expires: new Date(Date.now() + 1e3 * n.maxAge),
                httpOnly: !0,
                secure: r,
                path: null !== (i = n.path) && void 0 !== i ? i : "/",
                domain: null !== (o = n.domain) && void 0 !== o ? o : "",
                sameSite: null !== (s = n.sameSite) && void 0 !== s ? s : "lax",
              })
            );
            var n, r, i, o, s;
          }),
          i = t.getHeader("Set-Cookie");
        return (
          i &&
            (i instanceof Array
              ? Array.prototype.push.apply(r, i)
              : "string" == typeof i && r.push(i)),
          r
        );
      }
      function T(e, t, n) {
        t.setHeader("Set-Cookie", k(e, t, n));
      }
      var z = function (e, t, n, r) {
        return new (n || (n = Promise))(function (i, o) {
          function s(e) {
            try {
              c(r.next(e));
            } catch (e) {
              o(e);
            }
          }
          function a(e) {
            try {
              c(r.throw(e));
            } catch (e) {
              o(e);
            }
          }
          function c(e) {
            var t;
            e.done
              ? i(e.value)
              : ((t = e.value),
                t instanceof n
                  ? t
                  : new n(function (e) {
                      e(t);
                    })).then(s, a);
          }
          c((r = r.apply(e, t || [])).next());
        });
      };
      function O(e) {
        return Math.round(Date.now() / 1e3) + e;
      }
      const L = () => "undefined" != typeof window;
      function S(e, t) {
        var n;
        t ||
          (t =
            (null ===
              (n =
                null === window || void 0 === window
                  ? void 0
                  : window.location) || void 0 === n
              ? void 0
              : n.href) || ""),
          (e = e.replace(/[\[\]]/g, "\\$&"));
        const r = new RegExp("[?&#]" + e + "(=([^&#]*)|&|#|$)").exec(t);
        return r
          ? r[2]
            ? decodeURIComponent(r[2].replace(/\+/g, " "))
            : ""
          : null;
      }
      const U = (e) => {
        let t;
        return (
          (t =
            e ||
            ("undefined" == typeof fetch
              ? (...e) =>
                  z(void 0, void 0, void 0, function* () {
                    return yield (yield s
                      .e(98)
                      .then(s.t.bind(s, 98, 23))).fetch(...e);
                  })
              : fetch)),
          (...e) => t(...e)
        );
      };
      var _ = function (e, t, n, r) {
        return new (n || (n = Promise))(function (i, o) {
          function s(e) {
            try {
              c(r.next(e));
            } catch (e) {
              o(e);
            }
          }
          function a(e) {
            try {
              c(r.throw(e));
            } catch (e) {
              o(e);
            }
          }
          function c(e) {
            var t;
            e.done
              ? i(e.value)
              : ((t = e.value),
                t instanceof n
                  ? t
                  : new n(function (e) {
                      e(t);
                    })).then(s, a);
          }
          c((r = r.apply(e, t || [])).next());
        });
      };
      class Q {
        constructor({
          url: e = "",
          headers: t = {},
          cookieOptions: n,
          fetch: r,
        }) {
          (this.url = e),
            (this.headers = t),
            (this.cookieOptions = Object.assign(Object.assign({}, B), n)),
            (this.fetch = U(r));
        }
        _createRequestHeaders(e) {
          const t = Object.assign({}, this.headers);
          return (t.Authorization = `Bearer ${e}`), t;
        }
        cookieName() {
          var e;
          return null !== (e = this.cookieOptions.name) && void 0 !== e
            ? e
            : "";
        }
        getUrlForProvider(e, t) {
          const n = [`provider=${encodeURIComponent(e)}`];
          if (
            ((null == t ? void 0 : t.redirectTo) &&
              n.push(`redirect_to=${encodeURIComponent(t.redirectTo)}`),
            (null == t ? void 0 : t.scopes) &&
              n.push(`scopes=${encodeURIComponent(t.scopes)}`),
            null == t ? void 0 : t.queryParams)
          ) {
            const e = new URLSearchParams(t.queryParams);
            n.push(`${e}`);
          }
          return `${this.url}/authorize?${n.join("&")}`;
        }
        signUpWithEmail(e, t, n = {}) {
          return _(this, void 0, void 0, function* () {
            try {
              const r = Object.assign({}, this.headers);
              let i = "";
              n.redirectTo &&
                (i = "?redirect_to=" + encodeURIComponent(n.redirectTo));
              const o = yield D(
                  this.fetch,
                  `${this.url}/signup${i}`,
                  {
                    email: e,
                    password: t,
                    data: n.data,
                    gotrue_meta_security: { captcha_token: n.captchaToken },
                  },
                  { headers: r }
                ),
                s = Object.assign({}, o);
              return (
                s.expires_in && (s.expires_at = O(o.expires_in)),
                { data: s, error: null }
              );
            } catch (e) {
              return { data: null, error: e };
            }
          });
        }
        signInWithEmail(e, t, n = {}) {
          return _(this, void 0, void 0, function* () {
            try {
              const r = Object.assign({}, this.headers);
              let i = "?grant_type=password";
              n.redirectTo &&
                (i += "&redirect_to=" + encodeURIComponent(n.redirectTo));
              const o = yield D(
                  this.fetch,
                  `${this.url}/token${i}`,
                  {
                    email: e,
                    password: t,
                    gotrue_meta_security: { captcha_token: n.captchaToken },
                  },
                  { headers: r }
                ),
                s = Object.assign({}, o);
              return (
                s.expires_in && (s.expires_at = O(o.expires_in)),
                { data: s, error: null }
              );
            } catch (e) {
              return { data: null, error: e };
            }
          });
        }
        signUpWithPhone(e, t, n = {}) {
          return _(this, void 0, void 0, function* () {
            try {
              const r = Object.assign({}, this.headers),
                i = yield D(
                  this.fetch,
                  `${this.url}/signup`,
                  {
                    phone: e,
                    password: t,
                    data: n.data,
                    gotrue_meta_security: { captcha_token: n.captchaToken },
                  },
                  { headers: r }
                ),
                o = Object.assign({}, i);
              return (
                o.expires_in && (o.expires_at = O(i.expires_in)),
                { data: o, error: null }
              );
            } catch (e) {
              return { data: null, error: e };
            }
          });
        }
        signInWithPhone(e, t, n = {}) {
          return _(this, void 0, void 0, function* () {
            try {
              const r = Object.assign({}, this.headers),
                i = "?grant_type=password",
                o = yield D(
                  this.fetch,
                  `${this.url}/token${i}`,
                  {
                    phone: e,
                    password: t,
                    gotrue_meta_security: { captcha_token: n.captchaToken },
                  },
                  { headers: r }
                ),
                s = Object.assign({}, o);
              return (
                s.expires_in && (s.expires_at = O(o.expires_in)),
                { data: s, error: null }
              );
            } catch (e) {
              return { data: null, error: e };
            }
          });
        }
        signInWithOpenIDConnect({
          id_token: e,
          nonce: t,
          client_id: n,
          issuer: r,
          provider: i,
        }) {
          return _(this, void 0, void 0, function* () {
            try {
              const o = Object.assign({}, this.headers),
                s = "?grant_type=id_token",
                a = yield D(
                  this.fetch,
                  `${this.url}/token${s}`,
                  {
                    id_token: e,
                    nonce: t,
                    client_id: n,
                    issuer: r,
                    provider: i,
                  },
                  { headers: o }
                ),
                c = Object.assign({}, a);
              return (
                c.expires_in && (c.expires_at = O(a.expires_in)),
                { data: c, error: null }
              );
            } catch (e) {
              return { data: null, error: e };
            }
          });
        }
        sendMagicLinkEmail(e, t = {}) {
          var n;
          return _(this, void 0, void 0, function* () {
            try {
              const r = Object.assign({}, this.headers);
              let i = "";
              t.redirectTo &&
                (i += "?redirect_to=" + encodeURIComponent(t.redirectTo));
              const o = null === (n = t.shouldCreateUser) || void 0 === n || n;
              return {
                data: yield D(
                  this.fetch,
                  `${this.url}/otp${i}`,
                  {
                    email: e,
                    create_user: o,
                    gotrue_meta_security: { captcha_token: t.captchaToken },
                  },
                  { headers: r }
                ),
                error: null,
              };
            } catch (e) {
              return { data: null, error: e };
            }
          });
        }
        sendMobileOTP(e, t = {}) {
          var n;
          return _(this, void 0, void 0, function* () {
            try {
              const r = null === (n = t.shouldCreateUser) || void 0 === n || n,
                i = Object.assign({}, this.headers);
              return {
                data: yield D(
                  this.fetch,
                  `${this.url}/otp`,
                  {
                    phone: e,
                    create_user: r,
                    gotrue_meta_security: { captcha_token: t.captchaToken },
                  },
                  { headers: i }
                ),
                error: null,
              };
            } catch (e) {
              return { data: null, error: e };
            }
          });
        }
        signOut(e) {
          return _(this, void 0, void 0, function* () {
            try {
              return (
                yield D(
                  this.fetch,
                  `${this.url}/logout`,
                  {},
                  { headers: this._createRequestHeaders(e), noResolveJson: !0 }
                ),
                { error: null }
              );
            } catch (e) {
              return { error: e };
            }
          });
        }
        verifyMobileOTP(e, t, n = {}) {
          return _(this, void 0, void 0, function* () {
            try {
              const r = Object.assign({}, this.headers),
                i = yield D(
                  this.fetch,
                  `${this.url}/verify`,
                  {
                    phone: e,
                    token: t,
                    type: "sms",
                    redirect_to: n.redirectTo,
                  },
                  { headers: r }
                ),
                o = Object.assign({}, i);
              return (
                o.expires_in && (o.expires_at = O(i.expires_in)),
                { data: o, error: null }
              );
            } catch (e) {
              return { data: null, error: e };
            }
          });
        }
        verifyOTP({ email: e, phone: t, token: n, type: r = "sms" }, i = {}) {
          return _(this, void 0, void 0, function* () {
            try {
              const o = Object.assign({}, this.headers),
                s = yield D(
                  this.fetch,
                  `${this.url}/verify`,
                  {
                    email: e,
                    phone: t,
                    token: n,
                    type: r,
                    redirect_to: i.redirectTo,
                  },
                  { headers: o }
                ),
                a = Object.assign({}, s);
              return (
                a.expires_in && (a.expires_at = O(s.expires_in)),
                { data: a, error: null }
              );
            } catch (e) {
              return { data: null, error: e };
            }
          });
        }
        inviteUserByEmail(e, t = {}) {
          return _(this, void 0, void 0, function* () {
            try {
              const n = Object.assign({}, this.headers);
              let r = "";
              return (
                t.redirectTo &&
                  (r += "?redirect_to=" + encodeURIComponent(t.redirectTo)),
                {
                  data: yield D(
                    this.fetch,
                    `${this.url}/invite${r}`,
                    { email: e, data: t.data },
                    { headers: n }
                  ),
                  error: null,
                }
              );
            } catch (e) {
              return { data: null, error: e };
            }
          });
        }
        resetPasswordForEmail(e, t = {}) {
          return _(this, void 0, void 0, function* () {
            try {
              const n = Object.assign({}, this.headers);
              let r = "";
              return (
                t.redirectTo &&
                  (r += "?redirect_to=" + encodeURIComponent(t.redirectTo)),
                {
                  data: yield D(
                    this.fetch,
                    `${this.url}/recover${r}`,
                    {
                      email: e,
                      gotrue_meta_security: { captcha_token: t.captchaToken },
                    },
                    { headers: n }
                  ),
                  error: null,
                }
              );
            } catch (e) {
              return { data: null, error: e };
            }
          });
        }
        refreshAccessToken(e) {
          return _(this, void 0, void 0, function* () {
            try {
              const t = yield D(
                  this.fetch,
                  `${this.url}/token?grant_type=refresh_token`,
                  { refresh_token: e },
                  { headers: this.headers }
                ),
                n = Object.assign({}, t);
              return (
                n.expires_in && (n.expires_at = O(t.expires_in)),
                { data: n, error: null }
              );
            } catch (e) {
              return { data: null, error: e };
            }
          });
        }
        setAuthCookie(e, t) {
          "POST" !== e.method &&
            (t.setHeader("Allow", "POST"),
            t.status(405).end("Method Not Allowed"));
          const { event: n, session: r } = e.body;
          if (!n) throw new Error("Auth event missing!");
          if ("SIGNED_IN" === n) {
            if (!r) throw new Error("Auth session missing!");
            T(
              e,
              t,
              [
                { key: "access-token", value: r.access_token },
                { key: "refresh-token", value: r.refresh_token },
              ].map((e) => {
                var t;
                return {
                  name: `${this.cookieName()}-${e.key}`,
                  value: e.value,
                  domain: this.cookieOptions.domain,
                  maxAge:
                    null !== (t = this.cookieOptions.lifetime) && void 0 !== t
                      ? t
                      : 0,
                  path: this.cookieOptions.path,
                  sameSite: this.cookieOptions.sameSite,
                };
              })
            );
          }
          "SIGNED_OUT" === n &&
            T(
              e,
              t,
              ["access-token", "refresh-token"].map((e) => ({
                name: `${this.cookieName()}-${e}`,
                value: "",
                maxAge: -1,
              }))
            ),
            t.status(200).json({});
        }
        deleteAuthCookie(e, t, { redirectTo: n = "/" }) {
          return (
            T(
              e,
              t,
              ["access-token", "refresh-token"].map((e) => ({
                name: `${this.cookieName()}-${e}`,
                value: "",
                maxAge: -1,
              }))
            ),
            t.redirect(307, n)
          );
        }
        getAuthCookieString(e, t) {
          "POST" !== e.method &&
            (t.setHeader("Allow", "POST"),
            t.status(405).end("Method Not Allowed"));
          const { event: n, session: r } = e.body;
          if (!n) throw new Error("Auth event missing!");
          if ("SIGNED_IN" === n) {
            if (!r) throw new Error("Auth session missing!");
            return k(
              e,
              t,
              [
                { key: "access-token", value: r.access_token },
                { key: "refresh-token", value: r.refresh_token },
              ].map((e) => {
                var t;
                return {
                  name: `${this.cookieName()}-${e.key}`,
                  value: e.value,
                  domain: this.cookieOptions.domain,
                  maxAge:
                    null !== (t = this.cookieOptions.lifetime) && void 0 !== t
                      ? t
                      : 0,
                  path: this.cookieOptions.path,
                  sameSite: this.cookieOptions.sameSite,
                };
              })
            );
          }
          return "SIGNED_OUT" === n
            ? k(
                e,
                t,
                ["access-token", "refresh-token"].map((e) => ({
                  name: `${this.cookieName()}-${e}`,
                  value: "",
                  maxAge: -1,
                }))
              )
            : t.getHeader("Set-Cookie");
        }
        generateLink(e, t, n = {}) {
          return _(this, void 0, void 0, function* () {
            try {
              return {
                data: yield D(
                  this.fetch,
                  `${this.url}/admin/generate_link`,
                  {
                    type: e,
                    email: t,
                    password: n.password,
                    data: n.data,
                    redirect_to: n.redirectTo,
                  },
                  { headers: this.headers }
                ),
                error: null,
              };
            } catch (e) {
              return { data: null, error: e };
            }
          });
        }
        createUser(e) {
          return _(this, void 0, void 0, function* () {
            try {
              const t = yield D(this.fetch, `${this.url}/admin/users`, e, {
                headers: this.headers,
              });
              return { user: t, data: t, error: null };
            } catch (e) {
              return { user: null, data: null, error: e };
            }
          });
        }
        listUsers() {
          return _(this, void 0, void 0, function* () {
            try {
              return {
                data: (yield I(this.fetch, `${this.url}/admin/users`, {
                  headers: this.headers,
                })).users,
                error: null,
              };
            } catch (e) {
              return { data: null, error: e };
            }
          });
        }
        getUserById(e) {
          return _(this, void 0, void 0, function* () {
            try {
              return {
                data: yield I(this.fetch, `${this.url}/admin/users/${e}`, {
                  headers: this.headers,
                }),
                error: null,
              };
            } catch (e) {
              return { data: null, error: e };
            }
          });
        }
        getUserByCookie(e, t) {
          return _(this, void 0, void 0, function* () {
            try {
              if (!e.cookies)
                throw new Error(
                  "Not able to parse cookies! When using Express make sure the cookie-parser middleware is in use!"
                );
              const n = e.cookies[`${this.cookieName()}-access-token`],
                r = e.cookies[`${this.cookieName()}-refresh-token`];
              if (!n) throw new Error("No cookie found!");
              const { user: i, error: o } = yield this.getUser(n);
              if (o) {
                if (!r) throw new Error("No refresh_token cookie found!");
                if (!t)
                  throw new Error(
                    "You need to pass the res object to automatically refresh the session!"
                  );
                const { data: n, error: i } = yield this.refreshAccessToken(r);
                if (i) throw i;
                if (n)
                  return (
                    T(
                      e,
                      t,
                      [
                        { key: "access-token", value: n.access_token },
                        { key: "refresh-token", value: n.refresh_token },
                      ].map((e) => {
                        var t;
                        return {
                          name: `${this.cookieName()}-${e.key}`,
                          value: e.value,
                          domain: this.cookieOptions.domain,
                          maxAge:
                            null !== (t = this.cookieOptions.lifetime) &&
                            void 0 !== t
                              ? t
                              : 0,
                          path: this.cookieOptions.path,
                          sameSite: this.cookieOptions.sameSite,
                        };
                      })
                    ),
                    {
                      token: n.access_token,
                      user: n.user,
                      data: n.user,
                      error: null,
                    }
                  );
              }
              return { token: n, user: i, data: i, error: null };
            } catch (e) {
              return { token: null, user: null, data: null, error: e };
            }
          });
        }
        updateUserById(e, t) {
          return _(this, void 0, void 0, function* () {
            try {
              const n = yield j(this.fetch, `${this.url}/admin/users/${e}`, t, {
                headers: this.headers,
              });
              return { user: n, data: n, error: null };
            } catch (e) {
              return { user: null, data: null, error: e };
            }
          });
        }
        deleteUser(e) {
          return _(this, void 0, void 0, function* () {
            try {
              const t = yield (function (e, t, n, r) {
                return v(this, void 0, void 0, function* () {
                  return N(e, "DELETE", t, r, n);
                });
              })(
                this.fetch,
                `${this.url}/admin/users/${e}`,
                {},
                { headers: this.headers }
              );
              return { user: t, data: t, error: null };
            } catch (e) {
              return { user: null, data: null, error: e };
            }
          });
        }
        getUser(e) {
          return _(this, void 0, void 0, function* () {
            try {
              const t = yield I(this.fetch, `${this.url}/user`, {
                headers: this._createRequestHeaders(e),
              });
              return { user: t, data: t, error: null };
            } catch (e) {
              return { user: null, data: null, error: e };
            }
          });
        }
        updateUser(e, t) {
          return _(this, void 0, void 0, function* () {
            try {
              const n = yield j(this.fetch, `${this.url}/user`, t, {
                headers: this._createRequestHeaders(e),
              });
              return { user: n, data: n, error: null };
            } catch (e) {
              return { user: null, data: null, error: e };
            }
          });
        }
      }
      var P = function (e, t, n, r) {
        return new (n || (n = Promise))(function (i, o) {
          function s(e) {
            try {
              c(r.next(e));
            } catch (e) {
              o(e);
            }
          }
          function a(e) {
            try {
              c(r.throw(e));
            } catch (e) {
              o(e);
            }
          }
          function c(e) {
            var t;
            e.done
              ? i(e.value)
              : ((t = e.value),
                t instanceof n
                  ? t
                  : new n(function (e) {
                      e(t);
                    })).then(s, a);
          }
          c((r = r.apply(e, t || [])).next());
        });
      };
      !(function () {
        if ("object" != typeof globalThis)
          try {
            Object.defineProperty(Object.prototype, "__magic__", {
              get: function () {
                return this;
              },
              configurable: !0,
            }),
              (__magic__.globalThis = __magic__),
              delete Object.prototype.__magic__;
          } catch (e) {
            "undefined" != typeof self && (self.globalThis = self);
          }
      })();
      const R = {
        url: "http://localhost:9999",
        autoRefreshToken: !0,
        persistSession: !0,
        detectSessionInUrl: !0,
        multiTab: !0,
        headers: { "X-Client-Info": "gotrue-js/1.22.22" },
      };
      class Y extends class {
        constructor(e) {
          (this.stateChangeEmitters = new Map()), (this.networkRetries = 0);
          const t = Object.assign(Object.assign({}, R), e);
          (this.currentUser = null),
            (this.currentSession = null),
            (this.autoRefreshToken = t.autoRefreshToken),
            (this.persistSession = t.persistSession),
            (this.multiTab = t.multiTab),
            (this.localStorage = t.localStorage || globalThis.localStorage),
            (this.api = new Q({
              url: t.url,
              headers: t.headers,
              cookieOptions: t.cookieOptions,
              fetch: t.fetch,
            })),
            this._recoverSession(),
            this._recoverAndRefresh(),
            this._listenForMultiTabEvents(),
            this._handleVisibilityChange(),
            t.detectSessionInUrl &&
              L() &&
              S("access_token") &&
              this.getSessionFromUrl({ storeSession: !0 }).then(
                ({ error: e }) => {
                  if (e) throw new Error("Error getting session from URL.");
                }
              );
        }
        signUp({ email: e, password: t, phone: n }, r = {}) {
          return P(this, void 0, void 0, function* () {
            try {
              this._removeSession();
              const { data: i, error: o } =
                n && t
                  ? yield this.api.signUpWithPhone(n, t, {
                      data: r.data,
                      captchaToken: r.captchaToken,
                    })
                  : yield this.api.signUpWithEmail(e, t, {
                      redirectTo: r.redirectTo,
                      data: r.data,
                      captchaToken: r.captchaToken,
                    });
              if (o) throw o;
              if (!i) throw "An error occurred on sign up.";
              let s = null,
                a = null;
              return (
                i.access_token &&
                  ((s = i),
                  (a = s.user),
                  this._saveSession(s),
                  this._notifyAllSubscribers("SIGNED_IN")),
                i.id && (a = i),
                { user: a, session: s, error: null }
              );
            } catch (e) {
              return { user: null, session: null, error: e };
            }
          });
        }
        signIn(
          {
            email: e,
            phone: t,
            password: n,
            refreshToken: r,
            provider: i,
            oidc: o,
          },
          s = {}
        ) {
          return P(this, void 0, void 0, function* () {
            try {
              if ((this._removeSession(), e && !n)) {
                const { error: t } = yield this.api.sendMagicLinkEmail(e, {
                  redirectTo: s.redirectTo,
                  shouldCreateUser: s.shouldCreateUser,
                  captchaToken: s.captchaToken,
                });
                return { user: null, session: null, error: t };
              }
              if (e && n)
                return this._handleEmailSignIn(e, n, {
                  redirectTo: s.redirectTo,
                  captchaToken: s.captchaToken,
                });
              if (t && !n) {
                const { error: e } = yield this.api.sendMobileOTP(t, {
                  shouldCreateUser: s.shouldCreateUser,
                  captchaToken: s.captchaToken,
                });
                return { user: null, session: null, error: e };
              }
              if (t && n) return this._handlePhoneSignIn(t, n);
              if (r) {
                const { error: e } = yield this._callRefreshToken(r);
                if (e) throw e;
                return {
                  user: this.currentUser,
                  session: this.currentSession,
                  error: null,
                };
              }
              if (i)
                return this._handleProviderSignIn(i, {
                  redirectTo: s.redirectTo,
                  scopes: s.scopes,
                  queryParams: s.queryParams,
                });
              if (o) return this._handleOpenIDConnectSignIn(o);
              throw new Error(
                "You must provide either an email, phone number, a third-party provider or OpenID Connect."
              );
            } catch (e) {
              return { user: null, session: null, error: e };
            }
          });
        }
        verifyOTP(e, t = {}) {
          return P(this, void 0, void 0, function* () {
            try {
              this._removeSession();
              const { data: n, error: r } = yield this.api.verifyOTP(e, t);
              if (r) throw r;
              if (!n) throw "An error occurred on token verification.";
              let i = null,
                o = null;
              return (
                n.access_token &&
                  ((i = n),
                  (o = i.user),
                  this._saveSession(i),
                  this._notifyAllSubscribers("SIGNED_IN")),
                n.id && (o = n),
                { user: o, session: i, error: null }
              );
            } catch (e) {
              return { user: null, session: null, error: e };
            }
          });
        }
        user() {
          return this.currentUser;
        }
        session() {
          return this.currentSession;
        }
        refreshSession() {
          var e;
          return P(this, void 0, void 0, function* () {
            try {
              if (
                !(null === (e = this.currentSession) || void 0 === e
                  ? void 0
                  : e.access_token)
              )
                throw new Error("Not logged in.");
              const { error: t } = yield this._callRefreshToken();
              if (t) throw t;
              return {
                data: this.currentSession,
                user: this.currentUser,
                error: null,
              };
            } catch (e) {
              return { data: null, user: null, error: e };
            }
          });
        }
        update(e) {
          var t;
          return P(this, void 0, void 0, function* () {
            try {
              if (
                !(null === (t = this.currentSession) || void 0 === t
                  ? void 0
                  : t.access_token)
              )
                throw new Error("Not logged in.");
              const { user: n, error: r } = yield this.api.updateUser(
                this.currentSession.access_token,
                e
              );
              if (r) throw r;
              if (!n) throw Error("Invalid user data.");
              const i = Object.assign(Object.assign({}, this.currentSession), {
                user: n,
              });
              return (
                this._saveSession(i),
                this._notifyAllSubscribers("USER_UPDATED"),
                { data: n, user: n, error: null }
              );
            } catch (e) {
              return { data: null, user: null, error: e };
            }
          });
        }
        setSession(e) {
          return P(this, void 0, void 0, function* () {
            try {
              if (!e) throw new Error("No current session.");
              const { data: t, error: n } = yield this.api.refreshAccessToken(
                e
              );
              return n
                ? { session: null, error: n }
                : (this._saveSession(t),
                  this._notifyAllSubscribers("SIGNED_IN"),
                  { session: t, error: null });
            } catch (e) {
              return { error: e, session: null };
            }
          });
        }
        setAuth(e) {
          return (
            (this.currentSession = Object.assign(
              Object.assign({}, this.currentSession),
              { access_token: e, token_type: "bearer", user: this.user() }
            )),
            this._notifyAllSubscribers("TOKEN_REFRESHED"),
            this.currentSession
          );
        }
        getSessionFromUrl(e) {
          return P(this, void 0, void 0, function* () {
            try {
              if (!L()) throw new Error("No browser detected.");
              const t = S("error_description");
              if (t) throw new Error(t);
              const n = S("provider_token"),
                r = S("access_token");
              if (!r) throw new Error("No access_token detected.");
              const i = S("expires_in");
              if (!i) throw new Error("No expires_in detected.");
              const o = S("refresh_token");
              if (!o) throw new Error("No refresh_token detected.");
              const s = S("token_type");
              if (!s) throw new Error("No token_type detected.");
              const a = Math.round(Date.now() / 1e3) + parseInt(i),
                { user: c, error: l } = yield this.api.getUser(r);
              if (l) throw l;
              const A = {
                provider_token: n,
                access_token: r,
                expires_in: parseInt(i),
                expires_at: a,
                refresh_token: o,
                token_type: s,
                user: c,
              };
              if (null == e ? void 0 : e.storeSession) {
                this._saveSession(A);
                const e = S("type");
                this._notifyAllSubscribers("SIGNED_IN"),
                  "recovery" === e &&
                    this._notifyAllSubscribers("PASSWORD_RECOVERY");
              }
              return (window.location.hash = ""), { data: A, error: null };
            } catch (e) {
              return { data: null, error: e };
            }
          });
        }
        signOut() {
          var e;
          return P(this, void 0, void 0, function* () {
            const t =
              null === (e = this.currentSession) || void 0 === e
                ? void 0
                : e.access_token;
            if (
              (this._removeSession(),
              this._notifyAllSubscribers("SIGNED_OUT"),
              t)
            ) {
              const { error: e } = yield this.api.signOut(t);
              if (e) return { error: e };
            }
            return { error: null };
          });
        }
        onAuthStateChange(e) {
          try {
            const t = "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(
                /[xy]/g,
                function (e) {
                  const t = (16 * Math.random()) | 0;
                  return ("x" == e ? t : (3 & t) | 8).toString(16);
                }
              ),
              n = {
                id: t,
                callback: e,
                unsubscribe: () => {
                  this.stateChangeEmitters.delete(t);
                },
              };
            return this.stateChangeEmitters.set(t, n), { data: n, error: null };
          } catch (e) {
            return { data: null, error: e };
          }
        }
        _handleEmailSignIn(e, t, n = {}) {
          var r, i;
          return P(this, void 0, void 0, function* () {
            try {
              const { data: o, error: s } = yield this.api.signInWithEmail(
                e,
                t,
                { redirectTo: n.redirectTo, captchaToken: n.captchaToken }
              );
              return s || !o
                ? { data: null, user: null, session: null, error: s }
                : (((null === (r = null == o ? void 0 : o.user) || void 0 === r
                    ? void 0
                    : r.confirmed_at) ||
                    (null === (i = null == o ? void 0 : o.user) || void 0 === i
                      ? void 0
                      : i.email_confirmed_at)) &&
                    (this._saveSession(o),
                    this._notifyAllSubscribers("SIGNED_IN")),
                  { data: o, user: o.user, session: o, error: null });
            } catch (e) {
              return { data: null, user: null, session: null, error: e };
            }
          });
        }
        _handlePhoneSignIn(e, t, n = {}) {
          var r;
          return P(this, void 0, void 0, function* () {
            try {
              const { data: i, error: o } = yield this.api.signInWithPhone(
                e,
                t,
                n
              );
              return o || !i
                ? { data: null, user: null, session: null, error: o }
                : ((null === (r = null == i ? void 0 : i.user) || void 0 === r
                    ? void 0
                    : r.phone_confirmed_at) &&
                    (this._saveSession(i),
                    this._notifyAllSubscribers("SIGNED_IN")),
                  { data: i, user: i.user, session: i, error: null });
            } catch (e) {
              return { data: null, user: null, session: null, error: e };
            }
          });
        }
        _handleProviderSignIn(e, t = {}) {
          const n = this.api.getUrlForProvider(e, {
            redirectTo: t.redirectTo,
            scopes: t.scopes,
            queryParams: t.queryParams,
          });
          try {
            return (
              L() && (window.location.href = n),
              {
                provider: e,
                url: n,
                data: null,
                session: null,
                user: null,
                error: null,
              }
            );
          } catch (t) {
            return n
              ? {
                  provider: e,
                  url: n,
                  data: null,
                  session: null,
                  user: null,
                  error: null,
                }
              : { data: null, user: null, session: null, error: t };
          }
        }
        _handleOpenIDConnectSignIn({
          id_token: e,
          nonce: t,
          client_id: n,
          issuer: r,
          provider: i,
        }) {
          return P(this, void 0, void 0, function* () {
            if (e && t && ((n && r) || i))
              try {
                const { data: o, error: s } =
                  yield this.api.signInWithOpenIDConnect({
                    id_token: e,
                    nonce: t,
                    client_id: n,
                    issuer: r,
                    provider: i,
                  });
                return s || !o
                  ? { user: null, session: null, error: s }
                  : (this._saveSession(o),
                    this._notifyAllSubscribers("SIGNED_IN"),
                    { user: o.user, session: o, error: null });
              } catch (e) {
                return { user: null, session: null, error: e };
              }
            throw new Error(
              "You must provide a OpenID Connect provider with your id token and nonce."
            );
          });
        }
        _recoverSession() {
          try {
            const e = ((e, t) => {
              const n =
                L() && (null == e ? void 0 : e.getItem("supabase.auth.token"));
              if (!n || "string" != typeof n) return null;
              try {
                return JSON.parse(n);
              } catch (e) {
                return n;
              }
            })(this.localStorage);
            if (!e) return null;
            const { currentSession: t, expiresAt: n } = e;
            n >= Math.round(Date.now() / 1e3) + 10 &&
              (null == t ? void 0 : t.user) &&
              (this._saveSession(t), this._notifyAllSubscribers("SIGNED_IN"));
          } catch (e) {
            console.log("error", e);
          }
        }
        _recoverAndRefresh() {
          return P(this, void 0, void 0, function* () {
            try {
              const t = yield ((e = this.localStorage),
              M,
              z(void 0, void 0, void 0, function* () {
                const t =
                  L() &&
                  (yield null == e ? void 0 : e.getItem("supabase.auth.token"));
                if (!t) return null;
                try {
                  return JSON.parse(t);
                } catch (e) {
                  return t;
                }
              }));
              if (!t) return null;
              const { currentSession: n, expiresAt: r } = t;
              if (r < Math.round(Date.now() / 1e3) + 10)
                if (this.autoRefreshToken && n.refresh_token) {
                  this.networkRetries++;
                  const { error: e } = yield this._callRefreshToken(
                    n.refresh_token
                  );
                  if (e) {
                    if (
                      (console.log(e.message),
                      e.message === C && this.networkRetries < 10)
                    )
                      return (
                        this.refreshTokenTimer &&
                          clearTimeout(this.refreshTokenTimer),
                        void (this.refreshTokenTimer = setTimeout(
                          () => this._recoverAndRefresh(),
                          100 * Math.pow(2, this.networkRetries)
                        ))
                      );
                    yield this._removeSession();
                  }
                  this.networkRetries = 0;
                } else this._removeSession();
              else
                n
                  ? (this._saveSession(n),
                    this._notifyAllSubscribers("SIGNED_IN"))
                  : (console.log("Current session is missing data."),
                    this._removeSession());
            } catch (e) {
              return console.error(e), null;
            }
            var e;
          });
        }
        _callRefreshToken(e) {
          var t;
          return (
            void 0 === e &&
              (e =
                null === (t = this.currentSession) || void 0 === t
                  ? void 0
                  : t.refresh_token),
            P(this, void 0, void 0, function* () {
              try {
                if (!e) throw new Error("No current session.");
                const { data: t, error: n } = yield this.api.refreshAccessToken(
                  e
                );
                if (n) throw n;
                if (!t) throw Error("Invalid session data.");
                return (
                  this._saveSession(t),
                  this._notifyAllSubscribers("TOKEN_REFRESHED"),
                  this._notifyAllSubscribers("SIGNED_IN"),
                  { data: t, error: null }
                );
              } catch (e) {
                return { data: null, error: e };
              }
            })
          );
        }
        _notifyAllSubscribers(e) {
          this.stateChangeEmitters.forEach((t) =>
            t.callback(e, this.currentSession)
          );
        }
        _saveSession(e) {
          (this.currentSession = e), (this.currentUser = e.user);
          const t = e.expires_at;
          if (t) {
            const e = t - Math.round(Date.now() / 1e3),
              n = e > 10 ? 10 : 0.5;
            this._startAutoRefreshToken(1e3 * (e - n));
          }
          this.persistSession &&
            e.expires_at &&
            this._persistSession(this.currentSession);
        }
        _persistSession(e) {
          const t = { currentSession: e, expiresAt: e.expires_at };
          ((e, t, n) => {
            z(void 0, void 0, void 0, function* () {
              L() &&
                (yield null == e
                  ? void 0
                  : e.setItem("supabase.auth.token", JSON.stringify(n)));
            });
          })(this.localStorage, 0, t);
        }
        _removeSession() {
          return P(this, void 0, void 0, function* () {
            var e;
            (this.currentSession = null),
              (this.currentUser = null),
              this.refreshTokenTimer && clearTimeout(this.refreshTokenTimer),
              (e = this.localStorage),
              z(void 0, void 0, void 0, function* () {
                L() &&
                  (yield null == e
                    ? void 0
                    : e.removeItem("supabase.auth.token"));
              });
          });
        }
        _startAutoRefreshToken(e) {
          this.refreshTokenTimer && clearTimeout(this.refreshTokenTimer),
            e <= 0 ||
              !this.autoRefreshToken ||
              ((this.refreshTokenTimer = setTimeout(
                () =>
                  P(this, void 0, void 0, function* () {
                    this.networkRetries++;
                    const { error: e } = yield this._callRefreshToken();
                    e || (this.networkRetries = 0),
                      (null == e ? void 0 : e.message) === C &&
                        this.networkRetries < 10 &&
                        this._startAutoRefreshToken(
                          100 * Math.pow(2, this.networkRetries)
                        );
                  }),
                e
              )),
              "function" == typeof this.refreshTokenTimer.unref &&
                this.refreshTokenTimer.unref());
        }
        _listenForMultiTabEvents() {
          if (
            !this.multiTab ||
            !L() ||
            !(null === window || void 0 === window
              ? void 0
              : window.addEventListener)
          )
            return !1;
          try {
            null === window ||
              void 0 === window ||
              window.addEventListener("storage", (e) => {
                var t;
                if (e.key === M) {
                  const n = JSON.parse(String(e.newValue));
                  (
                    null === (t = null == n ? void 0 : n.currentSession) ||
                    void 0 === t
                      ? void 0
                      : t.access_token
                  )
                    ? (this._saveSession(n.currentSession),
                      this._notifyAllSubscribers("SIGNED_IN"))
                    : (this._removeSession(),
                      this._notifyAllSubscribers("SIGNED_OUT"));
                }
              });
          } catch (e) {
            console.error("_listenForMultiTabEvents", e);
          }
        }
        _handleVisibilityChange() {
          if (
            !this.multiTab ||
            !L() ||
            !(null === window || void 0 === window
              ? void 0
              : window.addEventListener)
          )
            return !1;
          try {
            null === window ||
              void 0 === window ||
              window.addEventListener("visibilitychange", () => {
                "visible" === document.visibilityState &&
                  this._recoverAndRefresh();
              });
          } catch (e) {
            console.error("_handleVisibilityChange", e);
          }
        }
      } {
        constructor(e) {
          super(e);
        }
      }
      var $ = function (e, t, n, r) {
        return new (n || (n = Promise))(function (i, o) {
          function s(e) {
            try {
              c(r.next(e));
            } catch (e) {
              o(e);
            }
          }
          function a(e) {
            try {
              c(r.throw(e));
            } catch (e) {
              o(e);
            }
          }
          function c(e) {
            var t;
            e.done
              ? i(e.value)
              : ((t = e.value),
                t instanceof n
                  ? t
                  : new n(function (e) {
                      e(t);
                    })).then(s, a);
          }
          c((r = r.apply(e, t || [])).next());
        });
      };
      class G {
        constructor(e) {
          let t;
          Object.assign(this, e),
            (t = e.fetch
              ? e.fetch
              : "undefined" == typeof fetch
              ? (...e) =>
                  $(this, void 0, void 0, function* () {
                    return yield (yield s
                      .e(98)
                      .then(s.t.bind(s, 98, 23))).fetch(...e);
                  })
              : fetch),
            (this.fetch = (...e) => t(...e)),
            (this.shouldThrowOnError = e.shouldThrowOnError || !1),
            (this.allowEmpty = e.allowEmpty || !1);
        }
        throwOnError(e) {
          return null == e && (e = !0), (this.shouldThrowOnError = e), this;
        }
        then(e, t) {
          void 0 === this.schema ||
            (["GET", "HEAD"].includes(this.method)
              ? (this.headers["Accept-Profile"] = this.schema)
              : (this.headers["Content-Profile"] = this.schema)),
            "GET" !== this.method &&
              "HEAD" !== this.method &&
              (this.headers["Content-Type"] = "application/json");
          let n = this.fetch(this.url.toString(), {
            method: this.method,
            headers: this.headers,
            body: JSON.stringify(this.body),
            signal: this.signal,
          }).then((e) =>
            $(this, void 0, void 0, function* () {
              var t, n, r, i;
              let o = null,
                s = null,
                a = null,
                c = e.status,
                l = e.statusText;
              if (e.ok) {
                const i =
                  null === (t = this.headers.Prefer) || void 0 === t
                    ? void 0
                    : t.split(",").includes("return=minimal");
                if ("HEAD" !== this.method && !i) {
                  const t = yield e.text();
                  t &&
                    (s =
                      "text/csv" === this.headers.Accept ? t : JSON.parse(t));
                }
                const o =
                    null === (n = this.headers.Prefer) || void 0 === n
                      ? void 0
                      : n.match(/count=(exact|planned|estimated)/),
                  c =
                    null === (r = e.headers.get("content-range")) ||
                    void 0 === r
                      ? void 0
                      : r.split("/");
                o && c && c.length > 1 && (a = parseInt(c[1]));
              } else {
                const t = yield e.text();
                try {
                  o = JSON.parse(t);
                } catch (e) {
                  o = { message: t };
                }
                if (
                  (o &&
                    this.allowEmpty &&
                    (null === (i = null == o ? void 0 : o.details) ||
                    void 0 === i
                      ? void 0
                      : i.includes("Results contain 0 rows")) &&
                    ((o = null), (c = 200), (l = "OK")),
                  o && this.shouldThrowOnError)
                )
                  throw o;
              }
              return {
                error: o,
                data: s,
                count: a,
                status: c,
                statusText: l,
                body: s,
              };
            })
          );
          return (
            this.shouldThrowOnError ||
              (n = n.catch((e) => ({
                error: {
                  message: `FetchError: ${e.message}`,
                  details: "",
                  hint: "",
                  code: e.code || "",
                },
                data: null,
                body: null,
                count: null,
                status: 400,
                statusText: "Bad Request",
              }))),
            n.then(e, t)
          );
        }
      }
      class Z extends G {
        select(e = "*") {
          let t = !1;
          const n = e
            .split("")
            .map((e) => (/\s/.test(e) && !t ? "" : ('"' === e && (t = !t), e)))
            .join("");
          return this.url.searchParams.set("select", n), this;
        }
        order(
          e,
          { ascending: t = !0, nullsFirst: n = !1, foreignTable: r } = {}
        ) {
          const i = void 0 === r ? "order" : `${r}.order`,
            o = this.url.searchParams.get(i);
          return (
            this.url.searchParams.set(
              i,
              `${o ? `${o},` : ""}${e}.${t ? "asc" : "desc"}.${
                n ? "nullsfirst" : "nullslast"
              }`
            ),
            this
          );
        }
        limit(e, { foreignTable: t } = {}) {
          const n = void 0 === t ? "limit" : `${t}.limit`;
          return this.url.searchParams.set(n, `${e}`), this;
        }
        range(e, t, { foreignTable: n } = {}) {
          const r = void 0 === n ? "offset" : `${n}.offset`,
            i = void 0 === n ? "limit" : `${n}.limit`;
          return (
            this.url.searchParams.set(r, `${e}`),
            this.url.searchParams.set(i, "" + (t - e + 1)),
            this
          );
        }
        abortSignal(e) {
          return (this.signal = e), this;
        }
        single() {
          return (
            (this.headers.Accept = "application/vnd.pgrst.object+json"), this
          );
        }
        maybeSingle() {
          return (
            (this.headers.Accept = "application/vnd.pgrst.object+json"),
            (this.allowEmpty = !0),
            this
          );
        }
        csv() {
          return (this.headers.Accept = "text/csv"), this;
        }
      }
      class F extends Z {
        constructor() {
          super(...arguments),
            (this.cs = this.contains),
            (this.cd = this.containedBy),
            (this.sl = this.rangeLt),
            (this.sr = this.rangeGt),
            (this.nxl = this.rangeGte),
            (this.nxr = this.rangeLte),
            (this.adj = this.rangeAdjacent),
            (this.ov = this.overlaps);
        }
        not(e, t, n) {
          return this.url.searchParams.append(`${e}`, `not.${t}.${n}`), this;
        }
        or(e, { foreignTable: t } = {}) {
          const n = void 0 === t ? "or" : `${t}.or`;
          return this.url.searchParams.append(n, `(${e})`), this;
        }
        eq(e, t) {
          return this.url.searchParams.append(`${e}`, `eq.${t}`), this;
        }
        neq(e, t) {
          return this.url.searchParams.append(`${e}`, `neq.${t}`), this;
        }
        gt(e, t) {
          return this.url.searchParams.append(`${e}`, `gt.${t}`), this;
        }
        gte(e, t) {
          return this.url.searchParams.append(`${e}`, `gte.${t}`), this;
        }
        lt(e, t) {
          return this.url.searchParams.append(`${e}`, `lt.${t}`), this;
        }
        lte(e, t) {
          return this.url.searchParams.append(`${e}`, `lte.${t}`), this;
        }
        like(e, t) {
          return this.url.searchParams.append(`${e}`, `like.${t}`), this;
        }
        ilike(e, t) {
          return this.url.searchParams.append(`${e}`, `ilike.${t}`), this;
        }
        is(e, t) {
          return this.url.searchParams.append(`${e}`, `is.${t}`), this;
        }
        in(e, t) {
          const n = t
            .map((e) =>
              "string" == typeof e && new RegExp("[,()]").test(e)
                ? `"${e}"`
                : `${e}`
            )
            .join(",");
          return this.url.searchParams.append(`${e}`, `in.(${n})`), this;
        }
        contains(e, t) {
          return (
            "string" == typeof t
              ? this.url.searchParams.append(`${e}`, `cs.${t}`)
              : Array.isArray(t)
              ? this.url.searchParams.append(`${e}`, `cs.{${t.join(",")}}`)
              : this.url.searchParams.append(`${e}`, `cs.${JSON.stringify(t)}`),
            this
          );
        }
        containedBy(e, t) {
          return (
            "string" == typeof t
              ? this.url.searchParams.append(`${e}`, `cd.${t}`)
              : Array.isArray(t)
              ? this.url.searchParams.append(`${e}`, `cd.{${t.join(",")}}`)
              : this.url.searchParams.append(`${e}`, `cd.${JSON.stringify(t)}`),
            this
          );
        }
        rangeLt(e, t) {
          return this.url.searchParams.append(`${e}`, `sl.${t}`), this;
        }
        rangeGt(e, t) {
          return this.url.searchParams.append(`${e}`, `sr.${t}`), this;
        }
        rangeGte(e, t) {
          return this.url.searchParams.append(`${e}`, `nxl.${t}`), this;
        }
        rangeLte(e, t) {
          return this.url.searchParams.append(`${e}`, `nxr.${t}`), this;
        }
        rangeAdjacent(e, t) {
          return this.url.searchParams.append(`${e}`, `adj.${t}`), this;
        }
        overlaps(e, t) {
          return (
            "string" == typeof t
              ? this.url.searchParams.append(`${e}`, `ov.${t}`)
              : this.url.searchParams.append(`${e}`, `ov.{${t.join(",")}}`),
            this
          );
        }
        textSearch(e, t, { config: n, type: r = null } = {}) {
          let i = "";
          "plain" === r
            ? (i = "pl")
            : "phrase" === r
            ? (i = "ph")
            : "websearch" === r && (i = "w");
          const o = void 0 === n ? "" : `(${n})`;
          return this.url.searchParams.append(`${e}`, `${i}fts${o}.${t}`), this;
        }
        fts(e, t, { config: n } = {}) {
          const r = void 0 === n ? "" : `(${n})`;
          return this.url.searchParams.append(`${e}`, `fts${r}.${t}`), this;
        }
        plfts(e, t, { config: n } = {}) {
          const r = void 0 === n ? "" : `(${n})`;
          return this.url.searchParams.append(`${e}`, `plfts${r}.${t}`), this;
        }
        phfts(e, t, { config: n } = {}) {
          const r = void 0 === n ? "" : `(${n})`;
          return this.url.searchParams.append(`${e}`, `phfts${r}.${t}`), this;
        }
        wfts(e, t, { config: n } = {}) {
          const r = void 0 === n ? "" : `(${n})`;
          return this.url.searchParams.append(`${e}`, `wfts${r}.${t}`), this;
        }
        filter(e, t, n) {
          return this.url.searchParams.append(`${e}`, `${t}.${n}`), this;
        }
        match(e) {
          return (
            Object.keys(e).forEach((t) => {
              this.url.searchParams.append(`${t}`, `eq.${e[t]}`);
            }),
            this
          );
        }
      }
      class H extends G {
        constructor(
          e,
          { headers: t = {}, schema: n, fetch: r, shouldThrowOnError: i } = {}
        ) {
          super({ fetch: r, shouldThrowOnError: i }),
            (this.url = new URL(e)),
            (this.headers = Object.assign({}, t)),
            (this.schema = n);
        }
        select(e = "*", { head: t = !1, count: n = null } = {}) {
          this.method = "GET";
          let r = !1;
          const i = e
            .split("")
            .map((e) => (/\s/.test(e) && !r ? "" : ('"' === e && (r = !r), e)))
            .join("");
          return (
            this.url.searchParams.set("select", i),
            n && (this.headers.Prefer = `count=${n}`),
            t && (this.method = "HEAD"),
            new F(this)
          );
        }
        insert(
          e,
          {
            upsert: t = !1,
            onConflict: n,
            returning: r = "representation",
            count: i = null,
          } = {}
        ) {
          this.method = "POST";
          const o = [`return=${r}`];
          if (
            (t && o.push("resolution=merge-duplicates"),
            t && void 0 !== n && this.url.searchParams.set("on_conflict", n),
            (this.body = e),
            i && o.push(`count=${i}`),
            this.headers.Prefer && o.unshift(this.headers.Prefer),
            (this.headers.Prefer = o.join(",")),
            Array.isArray(e))
          ) {
            const t = e.reduce((e, t) => e.concat(Object.keys(t)), []);
            if (t.length > 0) {
              const e = [...new Set(t)].map((e) => `"${e}"`);
              this.url.searchParams.set("columns", e.join(","));
            }
          }
          return new F(this);
        }
        upsert(
          e,
          {
            onConflict: t,
            returning: n = "representation",
            count: r = null,
            ignoreDuplicates: i = !1,
          } = {}
        ) {
          this.method = "POST";
          const o = [
            `resolution=${i ? "ignore" : "merge"}-duplicates`,
            `return=${n}`,
          ];
          return (
            void 0 !== t && this.url.searchParams.set("on_conflict", t),
            (this.body = e),
            r && o.push(`count=${r}`),
            this.headers.Prefer && o.unshift(this.headers.Prefer),
            (this.headers.Prefer = o.join(",")),
            new F(this)
          );
        }
        update(e, { returning: t = "representation", count: n = null } = {}) {
          this.method = "PATCH";
          const r = [`return=${t}`];
          return (
            (this.body = e),
            n && r.push(`count=${n}`),
            this.headers.Prefer && r.unshift(this.headers.Prefer),
            (this.headers.Prefer = r.join(",")),
            new F(this)
          );
        }
        delete({ returning: e = "representation", count: t = null } = {}) {
          this.method = "DELETE";
          const n = [`return=${e}`];
          return (
            t && n.push(`count=${t}`),
            this.headers.Prefer && n.unshift(this.headers.Prefer),
            (this.headers.Prefer = n.join(",")),
            new F(this)
          );
        }
      }
      class W extends G {
        constructor(
          e,
          { headers: t = {}, schema: n, fetch: r, shouldThrowOnError: i } = {}
        ) {
          super({ fetch: r, shouldThrowOnError: i }),
            (this.url = new URL(e)),
            (this.headers = Object.assign({}, t)),
            (this.schema = n);
        }
        rpc(e, { head: t = !1, count: n = null } = {}) {
          return (
            t
              ? ((this.method = "HEAD"),
                e &&
                  Object.entries(e).forEach(([e, t]) => {
                    this.url.searchParams.append(e, t);
                  }))
              : ((this.method = "POST"), (this.body = e)),
            n &&
              (void 0 !== this.headers.Prefer
                ? (this.headers.Prefer += `,count=${n}`)
                : (this.headers.Prefer = `count=${n}`)),
            new F(this)
          );
        }
      }
      const J = { "X-Client-Info": "postgrest-js/0.37.4" };
      class q {
        constructor(
          e,
          { headers: t = {}, schema: n, fetch: r, throwOnError: i } = {}
        ) {
          (this.url = e),
            (this.headers = Object.assign(Object.assign({}, J), t)),
            (this.schema = n),
            (this.fetch = r),
            (this.shouldThrowOnError = i);
        }
        auth(e) {
          return (this.headers.Authorization = `Bearer ${e}`), this;
        }
        from(e) {
          const t = `${this.url}/${e}`;
          return new H(t, {
            headers: this.headers,
            schema: this.schema,
            fetch: this.fetch,
            shouldThrowOnError: this.shouldThrowOnError,
          });
        }
        rpc(e, t, { head: n = !1, count: r = null } = {}) {
          const i = `${this.url}/rpc/${e}`;
          return new W(i, {
            headers: this.headers,
            schema: this.schema,
            fetch: this.fetch,
            shouldThrowOnError: this.shouldThrowOnError,
          }).rpc(t, { head: n, count: r });
        }
      }
      var X;
      !(function (e) {
        (e.abstime = "abstime"),
          (e.bool = "bool"),
          (e.date = "date"),
          (e.daterange = "daterange"),
          (e.float4 = "float4"),
          (e.float8 = "float8"),
          (e.int2 = "int2"),
          (e.int4 = "int4"),
          (e.int4range = "int4range"),
          (e.int8 = "int8"),
          (e.int8range = "int8range"),
          (e.json = "json"),
          (e.jsonb = "jsonb"),
          (e.money = "money"),
          (e.numeric = "numeric"),
          (e.oid = "oid"),
          (e.reltime = "reltime"),
          (e.text = "text"),
          (e.time = "time"),
          (e.timestamp = "timestamp"),
          (e.timestamptz = "timestamptz"),
          (e.timetz = "timetz"),
          (e.tsrange = "tsrange"),
          (e.tstzrange = "tstzrange");
      })(X || (X = {}));
      const V = (e, t, n = {}) => {
          var r;
          const i = null !== (r = n.skipTypes) && void 0 !== r ? r : [];
          return Object.keys(t).reduce(
            (n, r) => ((n[r] = K(r, e, t, i)), n),
            {}
          );
        },
        K = (e, t, n, r) => {
          const i = t.find((t) => t.name === e),
            o = null == i ? void 0 : i.type,
            s = n[e];
          return o && !r.includes(o) ? ee(o, s) : te(s);
        },
        ee = (e, t) => {
          if ("_" === e.charAt(0)) {
            const n = e.slice(1, e.length);
            return oe(t, n);
          }
          switch (e) {
            case X.bool:
              return ne(t);
            case X.float4:
            case X.float8:
            case X.int2:
            case X.int4:
            case X.int8:
            case X.numeric:
            case X.oid:
              return re(t);
            case X.json:
            case X.jsonb:
              return ie(t);
            case X.timestamp:
              return se(t);
            case X.abstime:
            case X.date:
            case X.daterange:
            case X.int4range:
            case X.int8range:
            case X.money:
            case X.reltime:
            case X.text:
            case X.time:
            case X.timestamptz:
            case X.timetz:
            case X.tsrange:
            case X.tstzrange:
            default:
              return te(t);
          }
        },
        te = (e) => e,
        ne = (e) => {
          switch (e) {
            case "t":
              return !0;
            case "f":
              return !1;
            default:
              return e;
          }
        },
        re = (e) => {
          if ("string" == typeof e) {
            const t = parseFloat(e);
            if (!Number.isNaN(t)) return t;
          }
          return e;
        },
        ie = (e) => {
          if ("string" == typeof e)
            try {
              return JSON.parse(e);
            } catch (t) {
              return console.log(`JSON parse error: ${t}`), e;
            }
          return e;
        },
        oe = (e, t) => {
          if ("string" != typeof e) return e;
          const n = e.length - 1,
            r = e[n];
          if ("{" === e[0] && "}" === r) {
            let r;
            const i = e.slice(1, n);
            try {
              r = JSON.parse("[" + i + "]");
            } catch (e) {
              r = i ? i.split(",") : [];
            }
            return r.map((e) => ee(t, e));
          }
          return e;
        },
        se = (e) => ("string" == typeof e ? e.replace(" ", "T") : e);
      var ae = s(840);
      const ce = { "X-Client-Info": "realtime-js/1.7.4" };
      var le, Ae, de, ue, he;
      !(function (e) {
        (e[(e.connecting = 0)] = "connecting"),
          (e[(e.open = 1)] = "open"),
          (e[(e.closing = 2)] = "closing"),
          (e[(e.closed = 3)] = "closed");
      })(le || (le = {})),
        (function (e) {
          (e.closed = "closed"),
            (e.errored = "errored"),
            (e.joined = "joined"),
            (e.joining = "joining"),
            (e.leaving = "leaving");
        })(Ae || (Ae = {})),
        (function (e) {
          (e.close = "phx_close"),
            (e.error = "phx_error"),
            (e.join = "phx_join"),
            (e.reply = "phx_reply"),
            (e.leave = "phx_leave"),
            (e.access_token = "access_token");
        })(de || (de = {})),
        (function (e) {
          e.websocket = "websocket";
        })(ue || (ue = {})),
        (function (e) {
          (e.Connecting = "connecting"),
            (e.Open = "open"),
            (e.Closing = "closing"),
            (e.Closed = "closed");
        })(he || (he = {}));
      class ge {
        constructor(e, t) {
          (this.callback = e),
            (this.timerCalc = t),
            (this.timer = void 0),
            (this.tries = 0),
            (this.callback = e),
            (this.timerCalc = t);
        }
        reset() {
          (this.tries = 0), clearTimeout(this.timer);
        }
        scheduleTimeout() {
          clearTimeout(this.timer),
            (this.timer = setTimeout(() => {
              (this.tries = this.tries + 1), this.callback();
            }, this.timerCalc(this.tries + 1)));
        }
      }
      class pe {
        constructor() {
          this.HEADER_LENGTH = 1;
        }
        decode(e, t) {
          return e.constructor === ArrayBuffer
            ? t(this._binaryDecode(e))
            : t("string" == typeof e ? JSON.parse(e) : {});
        }
        _binaryDecode(e) {
          const t = new DataView(e),
            n = new TextDecoder();
          return this._decodeBroadcast(e, t, n);
        }
        _decodeBroadcast(e, t, n) {
          const r = t.getUint8(1),
            i = t.getUint8(2);
          let o = this.HEADER_LENGTH + 2;
          const s = n.decode(e.slice(o, o + r));
          o += r;
          const a = n.decode(e.slice(o, o + i));
          return (
            (o += i),
            {
              ref: null,
              topic: s,
              event: a,
              payload: JSON.parse(n.decode(e.slice(o, e.byteLength))),
            }
          );
        }
      }
      class me {
        constructor(e, t, n = {}, r = 1e4) {
          (this.channel = e),
            (this.event = t),
            (this.payload = n),
            (this.timeout = r),
            (this.sent = !1),
            (this.timeoutTimer = void 0),
            (this.ref = ""),
            (this.receivedResp = null),
            (this.recHooks = []),
            (this.refEvent = null);
        }
        resend(e) {
          (this.timeout = e),
            this._cancelRefEvent(),
            (this.ref = ""),
            (this.refEvent = null),
            (this.receivedResp = null),
            (this.sent = !1),
            this.send();
        }
        send() {
          this._hasReceived("timeout") ||
            (this.startTimeout(),
            (this.sent = !0),
            this.channel.socket.push({
              topic: this.channel.topic,
              event: this.event,
              payload: this.payload,
              ref: this.ref,
            }));
        }
        updatePayload(e) {
          this.payload = Object.assign(Object.assign({}, this.payload), e);
        }
        receive(e, t) {
          var n;
          return (
            this._hasReceived(e) &&
              t(
                null === (n = this.receivedResp) || void 0 === n
                  ? void 0
                  : n.response
              ),
            this.recHooks.push({ status: e, callback: t }),
            this
          );
        }
        startTimeout() {
          this.timeoutTimer ||
            ((this.ref = this.channel.socket.makeRef()),
            (this.refEvent = this.channel.replyEventName(this.ref)),
            this.channel.on(this.refEvent, (e) => {
              this._cancelRefEvent(),
                this._cancelTimeout(),
                (this.receivedResp = e),
                this._matchReceive(e);
            }),
            (this.timeoutTimer = setTimeout(() => {
              this.trigger("timeout", {});
            }, this.timeout)));
        }
        trigger(e, t) {
          this.refEvent &&
            this.channel.trigger(this.refEvent, { status: e, response: t });
        }
        destroy() {
          this._cancelRefEvent(), this._cancelTimeout();
        }
        _cancelRefEvent() {
          this.refEvent && this.channel.off(this.refEvent);
        }
        _cancelTimeout() {
          clearTimeout(this.timeoutTimer), (this.timeoutTimer = void 0);
        }
        _matchReceive({ status: e, response: t }) {
          this.recHooks
            .filter((t) => t.status === e)
            .forEach((e) => e.callback(t));
        }
        _hasReceived(e) {
          return this.receivedResp && this.receivedResp.status === e;
        }
      }
      class we {
        constructor(e, t = {}, n) {
          (this.topic = e),
            (this.params = t),
            (this.socket = n),
            (this.bindings = []),
            (this.state = Ae.closed),
            (this.joinedOnce = !1),
            (this.pushBuffer = []),
            (this.timeout = this.socket.timeout),
            (this.joinPush = new me(this, de.join, this.params, this.timeout)),
            (this.rejoinTimer = new ge(
              () => this.rejoinUntilConnected(),
              this.socket.reconnectAfterMs
            )),
            this.joinPush.receive("ok", () => {
              (this.state = Ae.joined),
                this.rejoinTimer.reset(),
                this.pushBuffer.forEach((e) => e.send()),
                (this.pushBuffer = []);
            }),
            this.onClose(() => {
              this.rejoinTimer.reset(),
                this.socket.log(
                  "channel",
                  `close ${this.topic} ${this.joinRef()}`
                ),
                (this.state = Ae.closed),
                this.socket.remove(this);
            }),
            this.onError((e) => {
              this.isLeaving() ||
                this.isClosed() ||
                (this.socket.log("channel", `error ${this.topic}`, e),
                (this.state = Ae.errored),
                this.rejoinTimer.scheduleTimeout());
            }),
            this.joinPush.receive("timeout", () => {
              this.isJoining() &&
                (this.socket.log(
                  "channel",
                  `timeout ${this.topic}`,
                  this.joinPush.timeout
                ),
                (this.state = Ae.errored),
                this.rejoinTimer.scheduleTimeout());
            }),
            this.on(de.reply, (e, t) => {
              this.trigger(this.replyEventName(t), e);
            });
        }
        rejoinUntilConnected() {
          this.rejoinTimer.scheduleTimeout(),
            this.socket.isConnected() && this.rejoin();
        }
        subscribe(e = this.timeout) {
          if (this.joinedOnce)
            throw "tried to subscribe multiple times. 'subscribe' can only be called a single time per channel instance";
          return (this.joinedOnce = !0), this.rejoin(e), this.joinPush;
        }
        onClose(e) {
          this.on(de.close, e);
        }
        onError(e) {
          this.on(de.error, (t) => e(t));
        }
        on(e, t) {
          this.bindings.push({ event: e, callback: t });
        }
        off(e) {
          this.bindings = this.bindings.filter((t) => t.event !== e);
        }
        canPush() {
          return this.socket.isConnected() && this.isJoined();
        }
        push(e, t, n = this.timeout) {
          if (!this.joinedOnce)
            throw `tried to push '${e}' to '${this.topic}' before joining. Use channel.subscribe() before pushing events`;
          let r = new me(this, e, t, n);
          return (
            this.canPush()
              ? r.send()
              : (r.startTimeout(), this.pushBuffer.push(r)),
            r
          );
        }
        updateJoinPayload(e) {
          this.joinPush.updatePayload(e);
        }
        unsubscribe(e = this.timeout) {
          this.state = Ae.leaving;
          let t = () => {
            this.socket.log("channel", `leave ${this.topic}`),
              this.trigger(de.close, "leave", this.joinRef());
          };
          this.joinPush.destroy();
          let n = new me(this, de.leave, {}, e);
          return (
            n.receive("ok", () => t()).receive("timeout", () => t()),
            n.send(),
            this.canPush() || n.trigger("ok", {}),
            n
          );
        }
        onMessage(e, t, n) {
          return t;
        }
        isMember(e) {
          return this.topic === e;
        }
        joinRef() {
          return this.joinPush.ref;
        }
        rejoin(e = this.timeout) {
          this.isLeaving() ||
            (this.socket.leaveOpenTopic(this.topic),
            (this.state = Ae.joining),
            this.joinPush.resend(e));
        }
        trigger(e, t, n) {
          let { close: r, error: i, leave: o, join: s } = de;
          if (n && [r, i, o, s].indexOf(e) >= 0 && n !== this.joinRef()) return;
          let a = this.onMessage(e, t, n);
          if (t && !a)
            throw "channel onMessage callbacks must return the payload, modified or unmodified";
          this.bindings
            .filter((n) =>
              "*" === n.event
                ? e === (null == t ? void 0 : t.type)
                : n.event === e
            )
            .map((e) => e.callback(a, n));
        }
        replyEventName(e) {
          return `chan_reply_${e}`;
        }
        isClosed() {
          return this.state === Ae.closed;
        }
        isErrored() {
          return this.state === Ae.errored;
        }
        isJoined() {
          return this.state === Ae.joined;
        }
        isJoining() {
          return this.state === Ae.joining;
        }
        isLeaving() {
          return this.state === Ae.leaving;
        }
      }
      const Ee = () => {};
      class fe {
        constructor(e, t) {
          (this.accessToken = null),
            (this.channels = []),
            (this.endPoint = ""),
            (this.headers = ce),
            (this.params = {}),
            (this.timeout = 1e4),
            (this.transport = ae.w3cwebsocket),
            (this.heartbeatIntervalMs = 3e4),
            (this.longpollerTimeout = 2e4),
            (this.heartbeatTimer = void 0),
            (this.pendingHeartbeatRef = null),
            (this.ref = 0),
            (this.logger = Ee),
            (this.conn = null),
            (this.sendBuffer = []),
            (this.serializer = new pe()),
            (this.stateChangeCallbacks = {
              open: [],
              close: [],
              error: [],
              message: [],
            }),
            (this.endPoint = `${e}/${ue.websocket}`),
            (null == t ? void 0 : t.params) && (this.params = t.params),
            (null == t ? void 0 : t.headers) &&
              (this.headers = Object.assign(
                Object.assign({}, this.headers),
                t.headers
              )),
            (null == t ? void 0 : t.timeout) && (this.timeout = t.timeout),
            (null == t ? void 0 : t.logger) && (this.logger = t.logger),
            (null == t ? void 0 : t.transport) &&
              (this.transport = t.transport),
            (null == t ? void 0 : t.heartbeatIntervalMs) &&
              (this.heartbeatIntervalMs = t.heartbeatIntervalMs),
            (null == t ? void 0 : t.longpollerTimeout) &&
              (this.longpollerTimeout = t.longpollerTimeout),
            (this.reconnectAfterMs = (null == t ? void 0 : t.reconnectAfterMs)
              ? t.reconnectAfterMs
              : (e) => [1e3, 2e3, 5e3, 1e4][e - 1] || 1e4),
            (this.encode = (null == t ? void 0 : t.encode)
              ? t.encode
              : (e, t) => t(JSON.stringify(e))),
            (this.decode = (null == t ? void 0 : t.decode)
              ? t.decode
              : this.serializer.decode.bind(this.serializer)),
            (this.reconnectTimer = new ge(() => {
              return (
                (e = this),
                (t = void 0),
                (r = function* () {
                  yield this.disconnect(), this.connect();
                }),
                new ((n = void 0) || (n = Promise))(function (i, o) {
                  function s(e) {
                    try {
                      c(r.next(e));
                    } catch (e) {
                      o(e);
                    }
                  }
                  function a(e) {
                    try {
                      c(r.throw(e));
                    } catch (e) {
                      o(e);
                    }
                  }
                  function c(e) {
                    var t;
                    e.done
                      ? i(e.value)
                      : ((t = e.value),
                        t instanceof n
                          ? t
                          : new n(function (e) {
                              e(t);
                            })).then(s, a);
                  }
                  c((r = r.apply(e, t || [])).next());
                })
              );
              var e, t, n, r;
            }, this.reconnectAfterMs));
        }
        connect() {
          this.conn ||
            ((this.conn = new this.transport(
              this.endPointURL(),
              [],
              null,
              this.headers
            )),
            this.conn &&
              ((this.conn.binaryType = "arraybuffer"),
              (this.conn.onopen = () => this._onConnOpen()),
              (this.conn.onerror = (e) => this._onConnError(e)),
              (this.conn.onmessage = (e) => this.onConnMessage(e)),
              (this.conn.onclose = (e) => this._onConnClose(e))));
        }
        disconnect(e, t) {
          return new Promise((n, r) => {
            try {
              this.conn &&
                ((this.conn.onclose = function () {}),
                e ? this.conn.close(e, t || "") : this.conn.close(),
                (this.conn = null),
                this.heartbeatTimer && clearInterval(this.heartbeatTimer),
                this.reconnectTimer.reset()),
                n({ error: null, data: !0 });
            } catch (e) {
              n({ error: e, data: !1 });
            }
          });
        }
        log(e, t, n) {
          this.logger(e, t, n);
        }
        onOpen(e) {
          this.stateChangeCallbacks.open.push(e);
        }
        onClose(e) {
          this.stateChangeCallbacks.close.push(e);
        }
        onError(e) {
          this.stateChangeCallbacks.error.push(e);
        }
        onMessage(e) {
          this.stateChangeCallbacks.message.push(e);
        }
        connectionState() {
          switch (this.conn && this.conn.readyState) {
            case le.connecting:
              return he.Connecting;
            case le.open:
              return he.Open;
            case le.closing:
              return he.Closing;
            default:
              return he.Closed;
          }
        }
        isConnected() {
          return this.connectionState() === he.Open;
        }
        remove(e) {
          this.channels = this.channels.filter(
            (t) => t.joinRef() !== e.joinRef()
          );
        }
        channel(e, t = {}) {
          const n = new we(e, t, this);
          return this.channels.push(n), n;
        }
        push(e) {
          const { topic: t, event: n, payload: r, ref: i } = e;
          let o = () => {
            this.encode(e, (e) => {
              var t;
              null === (t = this.conn) || void 0 === t || t.send(e);
            });
          };
          this.log("push", `${t} ${n} (${i})`, r),
            this.isConnected() ? o() : this.sendBuffer.push(o);
        }
        onConnMessage(e) {
          this.decode(e.data, (e) => {
            let { topic: t, event: n, payload: r, ref: i } = e;
            ((i && i === this.pendingHeartbeatRef) ||
              n === (null == r ? void 0 : r.type)) &&
              (this.pendingHeartbeatRef = null),
              this.log(
                "receive",
                `${r.status || ""} ${t} ${n} ${(i && "(" + i + ")") || ""}`,
                r
              ),
              this.channels
                .filter((e) => e.isMember(t))
                .forEach((e) => e.trigger(n, r, i)),
              this.stateChangeCallbacks.message.forEach((t) => t(e));
          });
        }
        endPointURL() {
          return this._appendParams(
            this.endPoint,
            Object.assign({}, this.params, { vsn: "1.0.0" })
          );
        }
        makeRef() {
          let e = this.ref + 1;
          return (
            e === this.ref ? (this.ref = 0) : (this.ref = e),
            this.ref.toString()
          );
        }
        setAuth(e) {
          (this.accessToken = e),
            this.channels.forEach((t) => {
              e && t.updateJoinPayload({ user_token: e }),
                t.joinedOnce &&
                  t.isJoined() &&
                  t.push(de.access_token, { access_token: e });
            });
        }
        leaveOpenTopic(e) {
          let t = this.channels.find(
            (t) => t.topic === e && (t.isJoined() || t.isJoining())
          );
          t &&
            (this.log("transport", `leaving duplicate topic "${e}"`),
            t.unsubscribe());
        }
        _onConnOpen() {
          this.log("transport", `connected to ${this.endPointURL()}`),
            this._flushSendBuffer(),
            this.reconnectTimer.reset(),
            this.heartbeatTimer && clearInterval(this.heartbeatTimer),
            (this.heartbeatTimer = setInterval(
              () => this._sendHeartbeat(),
              this.heartbeatIntervalMs
            )),
            this.stateChangeCallbacks.open.forEach((e) => e());
        }
        _onConnClose(e) {
          this.log("transport", "close", e),
            this._triggerChanError(),
            this.heartbeatTimer && clearInterval(this.heartbeatTimer),
            this.reconnectTimer.scheduleTimeout(),
            this.stateChangeCallbacks.close.forEach((t) => t(e));
        }
        _onConnError(e) {
          this.log("transport", e.message),
            this._triggerChanError(),
            this.stateChangeCallbacks.error.forEach((t) => t(e));
        }
        _triggerChanError() {
          this.channels.forEach((e) => e.trigger(de.error));
        }
        _appendParams(e, t) {
          if (0 === Object.keys(t).length) return e;
          const n = e.match(/\?/) ? "&" : "?";
          return `${e}${n}${new URLSearchParams(t)}`;
        }
        _flushSendBuffer() {
          this.isConnected() &&
            this.sendBuffer.length > 0 &&
            (this.sendBuffer.forEach((e) => e()), (this.sendBuffer = []));
        }
        _sendHeartbeat() {
          var e;
          if (this.isConnected()) {
            if (this.pendingHeartbeatRef)
              return (
                (this.pendingHeartbeatRef = null),
                this.log(
                  "transport",
                  "heartbeat timeout. Attempting to re-establish connection"
                ),
                void (
                  null === (e = this.conn) ||
                  void 0 === e ||
                  e.close(1e3, "hearbeat timeout")
                )
              );
            (this.pendingHeartbeatRef = this.makeRef()),
              this.push({
                topic: "phoenix",
                event: "heartbeat",
                payload: {},
                ref: this.pendingHeartbeatRef,
              }),
              this.setAuth(this.accessToken);
          }
        }
      }
      class ye {
        constructor(e, t, n, r) {
          const i = {},
            o = "*" === r ? `realtime:${n}` : `realtime:${n}:${r}`,
            s = t.Authorization.split(" ")[1];
          s && (i.user_token = s), (this.subscription = e.channel(o, i));
        }
        getPayloadRecords(e) {
          const t = { new: {}, old: {} };
          return (
            ("INSERT" !== e.type && "UPDATE" !== e.type) ||
              (t.new = V(e.columns, e.record)),
            ("UPDATE" !== e.type && "DELETE" !== e.type) ||
              (t.old = V(e.columns, e.old_record)),
            t
          );
        }
        on(e, t) {
          return (
            this.subscription.on(e, (e) => {
              let n = {
                schema: e.schema,
                table: e.table,
                commit_timestamp: e.commit_timestamp,
                eventType: e.type,
                new: {},
                old: {},
                errors: e.errors,
              };
              (n = Object.assign(
                Object.assign({}, n),
                this.getPayloadRecords(e)
              )),
                t(n);
            }),
            this
          );
        }
        subscribe(e = () => {}) {
          return (
            this.subscription.onError((t) => e("SUBSCRIPTION_ERROR", t)),
            this.subscription.onClose(() => e("CLOSED")),
            this.subscription
              .subscribe()
              .receive("ok", () => e("SUBSCRIBED"))
              .receive("error", (t) => e("SUBSCRIPTION_ERROR", t))
              .receive("timeout", () => e("RETRYING_AFTER_TIMEOUT")),
            this.subscription
          );
        }
      }
      class be extends H {
        constructor(
          e,
          {
            headers: t = {},
            schema: n,
            realtime: r,
            table: i,
            fetch: o,
            shouldThrowOnError: s,
          }
        ) {
          super(e, { headers: t, schema: n, fetch: o, shouldThrowOnError: s }),
            (this._subscription = null),
            (this._realtime = r),
            (this._headers = t),
            (this._schema = n),
            (this._table = i);
        }
        on(e, t) {
          return (
            this._realtime.isConnected() || this._realtime.connect(),
            this._subscription ||
              (this._subscription = new ye(
                this._realtime,
                this._headers,
                this._schema,
                this._table
              )),
            this._subscription.on(e, t)
          );
        }
      }
      const Ce = { "X-Client-Info": "storage-js/1.7.3" };
      var Me = function (e, t, n, r) {
        return new (n || (n = Promise))(function (i, o) {
          function s(e) {
            try {
              c(r.next(e));
            } catch (e) {
              o(e);
            }
          }
          function a(e) {
            try {
              c(r.throw(e));
            } catch (e) {
              o(e);
            }
          }
          function c(e) {
            var t;
            e.done
              ? i(e.value)
              : ((t = e.value),
                t instanceof n
                  ? t
                  : new n(function (e) {
                      e(t);
                    })).then(s, a);
          }
          c((r = r.apply(e, t || [])).next());
        });
      };
      const Be = (e) =>
        e.msg ||
        e.message ||
        e.error_description ||
        e.error ||
        JSON.stringify(e);
      function ve(e, t, n, r, i, o) {
        return Me(this, void 0, void 0, function* () {
          return new Promise((s, a) => {
            e(
              n,
              ((e, t, n, r) => {
                const i = {
                  method: e,
                  headers: (null == t ? void 0 : t.headers) || {},
                };
                return "GET" === e
                  ? i
                  : ((i.headers = Object.assign(
                      { "Content-Type": "application/json" },
                      null == t ? void 0 : t.headers
                    )),
                    (i.body = JSON.stringify(r)),
                    Object.assign(Object.assign({}, i), n));
              })(t, r, i, o)
            )
              .then((e) => {
                if (!e.ok) throw e;
                return (null == r ? void 0 : r.noResolveJson) ? s(e) : e.json();
              })
              .then((e) => s(e))
              .catch((e) =>
                ((e, t) => {
                  if ("function" != typeof e.json) return t(e);
                  e.json().then((n) =>
                    t({
                      message: Be(n),
                      status: (null == e ? void 0 : e.status) || 500,
                    })
                  );
                })(e, a)
              );
          });
        });
      }
      function xe(e, t, n, r) {
        return Me(this, void 0, void 0, function* () {
          return ve(e, "GET", t, n, r);
        });
      }
      function Ne(e, t, n, r, i) {
        return Me(this, void 0, void 0, function* () {
          return ve(e, "POST", t, r, i, n);
        });
      }
      function Ie(e, t, n, r, i) {
        return Me(this, void 0, void 0, function* () {
          return ve(e, "DELETE", t, r, i, n);
        });
      }
      const De = (e) => {
        let t;
        return (
          (t =
            e ||
            ("undefined" == typeof fetch
              ? (...e) => {
                  return (
                    (t = void 0),
                    (n = void 0),
                    (i = function* () {
                      return yield (yield s
                        .e(98)
                        .then(s.t.bind(s, 98, 23))).fetch(...e);
                    }),
                    new ((r = void 0) || (r = Promise))(function (e, o) {
                      function s(e) {
                        try {
                          c(i.next(e));
                        } catch (e) {
                          o(e);
                        }
                      }
                      function a(e) {
                        try {
                          c(i.throw(e));
                        } catch (e) {
                          o(e);
                        }
                      }
                      function c(t) {
                        var n;
                        t.done
                          ? e(t.value)
                          : ((n = t.value),
                            n instanceof r
                              ? n
                              : new r(function (e) {
                                  e(n);
                                })).then(s, a);
                      }
                      c((i = i.apply(t, n || [])).next());
                    })
                  );
                  var t, n, r, i;
                }
              : fetch)),
          (...e) => t(...e)
        );
      };
      var je = function (e, t, n, r) {
          return new (n || (n = Promise))(function (i, o) {
            function s(e) {
              try {
                c(r.next(e));
              } catch (e) {
                o(e);
              }
            }
            function a(e) {
              try {
                c(r.throw(e));
              } catch (e) {
                o(e);
              }
            }
            function c(e) {
              var t;
              e.done
                ? i(e.value)
                : ((t = e.value),
                  t instanceof n
                    ? t
                    : new n(function (e) {
                        e(t);
                      })).then(s, a);
            }
            c((r = r.apply(e, t || [])).next());
          });
        },
        ke = function (e, t, n, r) {
          return new (n || (n = Promise))(function (i, o) {
            function s(e) {
              try {
                c(r.next(e));
              } catch (e) {
                o(e);
              }
            }
            function a(e) {
              try {
                c(r.throw(e));
              } catch (e) {
                o(e);
              }
            }
            function c(e) {
              var t;
              e.done
                ? i(e.value)
                : ((t = e.value),
                  t instanceof n
                    ? t
                    : new n(function (e) {
                        e(t);
                      })).then(s, a);
            }
            c((r = r.apply(e, t || [])).next());
          });
        };
      const Te = {
          limit: 100,
          offset: 0,
          sortBy: { column: "name", order: "asc" },
        },
        ze = {
          cacheControl: "3600",
          contentType: "text/plain;charset=UTF-8",
          upsert: !1,
        };
      class Oe {
        constructor(e, t = {}, n, r) {
          (this.url = e),
            (this.headers = t),
            (this.bucketId = n),
            (this.fetch = De(r));
        }
        uploadOrUpdate(e, t, n, r) {
          return ke(this, void 0, void 0, function* () {
            try {
              let i;
              const o = Object.assign(Object.assign({}, ze), r),
                s = Object.assign(
                  Object.assign({}, this.headers),
                  "POST" === e && { "x-upsert": String(o.upsert) }
                );
              "undefined" != typeof Blob && n instanceof Blob
                ? ((i = new FormData()),
                  i.append("cacheControl", o.cacheControl),
                  i.append("", n))
                : "undefined" != typeof FormData && n instanceof FormData
                ? ((i = n), i.append("cacheControl", o.cacheControl))
                : ((i = n),
                  (s["cache-control"] = `max-age=${o.cacheControl}`),
                  (s["content-type"] = o.contentType));
              const a = this._removeEmptyFolders(t),
                c = this._getFinalPath(a),
                l = yield this.fetch(`${this.url}/object/${c}`, {
                  method: e,
                  body: i,
                  headers: s,
                });
              return l.ok
                ? { data: { Key: c }, error: null }
                : { data: null, error: yield l.json() };
            } catch (e) {
              return { data: null, error: e };
            }
          });
        }
        upload(e, t, n) {
          return ke(this, void 0, void 0, function* () {
            return this.uploadOrUpdate("POST", e, t, n);
          });
        }
        update(e, t, n) {
          return ke(this, void 0, void 0, function* () {
            return this.uploadOrUpdate("PUT", e, t, n);
          });
        }
        move(e, t) {
          return ke(this, void 0, void 0, function* () {
            try {
              return {
                data: yield Ne(
                  this.fetch,
                  `${this.url}/object/move`,
                  { bucketId: this.bucketId, sourceKey: e, destinationKey: t },
                  { headers: this.headers }
                ),
                error: null,
              };
            } catch (e) {
              return { data: null, error: e };
            }
          });
        }
        copy(e, t) {
          return ke(this, void 0, void 0, function* () {
            try {
              return {
                data: yield Ne(
                  this.fetch,
                  `${this.url}/object/copy`,
                  { bucketId: this.bucketId, sourceKey: e, destinationKey: t },
                  { headers: this.headers }
                ),
                error: null,
              };
            } catch (e) {
              return { data: null, error: e };
            }
          });
        }
        createSignedUrl(e, t) {
          return ke(this, void 0, void 0, function* () {
            try {
              const n = this._getFinalPath(e);
              let r = yield Ne(
                this.fetch,
                `${this.url}/object/sign/${n}`,
                { expiresIn: t },
                { headers: this.headers }
              );
              const i = `${this.url}${r.signedURL}`;
              return (
                (r = { signedURL: i }), { data: r, error: null, signedURL: i }
              );
            } catch (e) {
              return { data: null, error: e, signedURL: null };
            }
          });
        }
        createSignedUrls(e, t) {
          return ke(this, void 0, void 0, function* () {
            try {
              return {
                data: (yield Ne(
                  this.fetch,
                  `${this.url}/object/sign/${this.bucketId}`,
                  { expiresIn: t, paths: e },
                  { headers: this.headers }
                )).map((e) =>
                  Object.assign(Object.assign({}, e), {
                    signedURL: e.signedURL ? `${this.url}${e.signedURL}` : null,
                  })
                ),
                error: null,
              };
            } catch (e) {
              return { data: null, error: e };
            }
          });
        }
        download(e) {
          return ke(this, void 0, void 0, function* () {
            try {
              const t = this._getFinalPath(e),
                n = yield xe(this.fetch, `${this.url}/object/${t}`, {
                  headers: this.headers,
                  noResolveJson: !0,
                });
              return { data: yield n.blob(), error: null };
            } catch (e) {
              return { data: null, error: e };
            }
          });
        }
        getPublicUrl(e) {
          try {
            const t = this._getFinalPath(e),
              n = `${this.url}/object/public/${t}`;
            return { data: { publicURL: n }, error: null, publicURL: n };
          } catch (e) {
            return { data: null, error: e, publicURL: null };
          }
        }
        remove(e) {
          return ke(this, void 0, void 0, function* () {
            try {
              return {
                data: yield Ie(
                  this.fetch,
                  `${this.url}/object/${this.bucketId}`,
                  { prefixes: e },
                  { headers: this.headers }
                ),
                error: null,
              };
            } catch (e) {
              return { data: null, error: e };
            }
          });
        }
        list(e, t, n) {
          return ke(this, void 0, void 0, function* () {
            try {
              const r = Object.assign(Object.assign(Object.assign({}, Te), t), {
                prefix: e || "",
              });
              return {
                data: yield Ne(
                  this.fetch,
                  `${this.url}/object/list/${this.bucketId}`,
                  r,
                  { headers: this.headers },
                  n
                ),
                error: null,
              };
            } catch (e) {
              return { data: null, error: e };
            }
          });
        }
        _getFinalPath(e) {
          return `${this.bucketId}/${e}`;
        }
        _removeEmptyFolders(e) {
          return e.replace(/^\/|\/$/g, "").replace(/\/+/g, "/");
        }
      }
      class Le extends class {
        constructor(e, t = {}, n) {
          (this.url = e),
            (this.headers = Object.assign(Object.assign({}, Ce), t)),
            (this.fetch = De(n));
        }
        listBuckets() {
          return je(this, void 0, void 0, function* () {
            try {
              return {
                data: yield xe(this.fetch, `${this.url}/bucket`, {
                  headers: this.headers,
                }),
                error: null,
              };
            } catch (e) {
              return { data: null, error: e };
            }
          });
        }
        getBucket(e) {
          return je(this, void 0, void 0, function* () {
            try {
              return {
                data: yield xe(this.fetch, `${this.url}/bucket/${e}`, {
                  headers: this.headers,
                }),
                error: null,
              };
            } catch (e) {
              return { data: null, error: e };
            }
          });
        }
        createBucket(e, t = { public: !1 }) {
          return je(this, void 0, void 0, function* () {
            try {
              return {
                data: (yield Ne(
                  this.fetch,
                  `${this.url}/bucket`,
                  { id: e, name: e, public: t.public },
                  { headers: this.headers }
                )).name,
                error: null,
              };
            } catch (e) {
              return { data: null, error: e };
            }
          });
        }
        updateBucket(e, t) {
          return je(this, void 0, void 0, function* () {
            try {
              const n = yield (function (e, t, n, r, i) {
                return Me(this, void 0, void 0, function* () {
                  return ve(e, "PUT", t, r, undefined, n);
                });
              })(
                this.fetch,
                `${this.url}/bucket/${e}`,
                { id: e, name: e, public: t.public },
                { headers: this.headers }
              );
              return { data: n, error: null };
            } catch (e) {
              return { data: null, error: e };
            }
          });
        }
        emptyBucket(e) {
          return je(this, void 0, void 0, function* () {
            try {
              return {
                data: yield Ne(
                  this.fetch,
                  `${this.url}/bucket/${e}/empty`,
                  {},
                  { headers: this.headers }
                ),
                error: null,
              };
            } catch (e) {
              return { data: null, error: e };
            }
          });
        }
        deleteBucket(e) {
          return je(this, void 0, void 0, function* () {
            try {
              return {
                data: yield Ie(
                  this.fetch,
                  `${this.url}/bucket/${e}`,
                  {},
                  { headers: this.headers }
                ),
                error: null,
              };
            } catch (e) {
              return { data: null, error: e };
            }
          });
        }
      } {
        constructor(e, t = {}, n) {
          super(e, t, n);
        }
        from(e) {
          return new Oe(this.url, this.headers, e, this.fetch);
        }
      }
      class Se {
        constructor(e, { headers: t = {}, customFetch: n } = {}) {
          (this.url = e),
            (this.headers = t),
            (this.fetch = ((e) => {
              let t;
              return (
                (t =
                  e ||
                  ("undefined" == typeof fetch
                    ? (...e) => {
                        return (
                          (t = void 0),
                          (n = void 0),
                          (i = function* () {
                            return yield (yield s
                              .e(98)
                              .then(s.t.bind(s, 98, 23))).fetch(...e);
                          }),
                          new ((r = void 0) || (r = Promise))(function (e, o) {
                            function s(e) {
                              try {
                                c(i.next(e));
                              } catch (e) {
                                o(e);
                              }
                            }
                            function a(e) {
                              try {
                                c(i.throw(e));
                              } catch (e) {
                                o(e);
                              }
                            }
                            function c(t) {
                              var n;
                              t.done
                                ? e(t.value)
                                : ((n = t.value),
                                  n instanceof r
                                    ? n
                                    : new r(function (e) {
                                        e(n);
                                      })).then(s, a);
                            }
                            c((i = i.apply(t, n || [])).next());
                          })
                        );
                        var t, n, r, i;
                      }
                    : fetch)),
                (...e) => t(...e)
              );
            })(n));
        }
        setAuth(e) {
          this.headers.Authorization = `Bearer ${e}`;
        }
        invoke(e, t) {
          return (
            (n = this),
            (r = void 0),
            (o = function* () {
              try {
                const { headers: n, body: r } = null != t ? t : {},
                  i = yield this.fetch(`${this.url}/${e}`, {
                    method: "POST",
                    headers: Object.assign({}, this.headers, n),
                    body: r,
                  }),
                  o = i.headers.get("x-relay-error");
                if (o && "true" === o)
                  return { data: null, error: new Error(yield i.text()) };
                let s;
                const { responseType: a } = null != t ? t : {};
                return (
                  (s =
                    a && "json" !== a
                      ? "arrayBuffer" === a
                        ? yield i.arrayBuffer()
                        : "blob" === a
                        ? yield i.blob()
                        : yield i.text()
                      : yield i.json()),
                  { data: s, error: null }
                );
              } catch (e) {
                return { data: null, error: e };
              }
            }),
            new ((i = void 0) || (i = Promise))(function (e, t) {
              function s(e) {
                try {
                  c(o.next(e));
                } catch (e) {
                  t(e);
                }
              }
              function a(e) {
                try {
                  c(o.throw(e));
                } catch (e) {
                  t(e);
                }
              }
              function c(t) {
                var n;
                t.done
                  ? e(t.value)
                  : ((n = t.value),
                    n instanceof i
                      ? n
                      : new i(function (e) {
                          e(n);
                        })).then(s, a);
              }
              c((o = o.apply(n, r || [])).next());
            })
          );
          var n, r, i, o;
        }
      }
      var Ue = function (e, t, n, r) {
        return new (n || (n = Promise))(function (i, o) {
          function s(e) {
            try {
              c(r.next(e));
            } catch (e) {
              o(e);
            }
          }
          function a(e) {
            try {
              c(r.throw(e));
            } catch (e) {
              o(e);
            }
          }
          function c(e) {
            var t;
            e.done
              ? i(e.value)
              : ((t = e.value),
                t instanceof n
                  ? t
                  : new n(function (e) {
                      e(t);
                    })).then(s, a);
          }
          c((r = r.apply(e, t || [])).next());
        });
      };
      const _e = {
        schema: "public",
        autoRefreshToken: !0,
        persistSession: !0,
        detectSessionInUrl: !0,
        multiTab: !0,
        headers: b,
      };
      class Qe {
        constructor(e, t, n) {
          if (((this.supabaseUrl = e), (this.supabaseKey = t), !e))
            throw new Error("supabaseUrl is required.");
          if (!t) throw new Error("supabaseKey is required.");
          const r = e.replace(/\/$/, ""),
            i = Object.assign(Object.assign({}, _e), n);
          if (
            ((this.restUrl = `${r}/rest/v1`),
            (this.realtimeUrl = `${r}/realtime/v1`.replace("http", "ws")),
            (this.authUrl = `${r}/auth/v1`),
            (this.storageUrl = `${r}/storage/v1`),
            r.match(/(supabase\.co)|(supabase\.in)/))
          ) {
            const e = r.split(".");
            this.functionsUrl = `${e[0]}.functions.${e[1]}.${e[2]}`;
          } else this.functionsUrl = `${r}/functions/v1`;
          (this.schema = i.schema),
            (this.multiTab = i.multiTab),
            (this.fetch = i.fetch),
            (this.headers = Object.assign(
              Object.assign({}, b),
              null == n ? void 0 : n.headers
            )),
            (this.shouldThrowOnError = i.shouldThrowOnError || !1),
            (this.auth = this._initSupabaseAuthClient(i)),
            (this.realtime = this._initRealtimeClient(
              Object.assign({ headers: this.headers }, i.realtime)
            )),
            this._listenForAuthEvents(),
            this._listenForMultiTabEvents();
        }
        get functions() {
          return new Se(this.functionsUrl, {
            headers: this._getAuthHeaders(),
            customFetch: this.fetch,
          });
        }
        get storage() {
          return new Le(this.storageUrl, this._getAuthHeaders(), this.fetch);
        }
        from(e) {
          const t = `${this.restUrl}/${e}`;
          return new be(t, {
            headers: this._getAuthHeaders(),
            schema: this.schema,
            realtime: this.realtime,
            table: e,
            fetch: this.fetch,
            shouldThrowOnError: this.shouldThrowOnError,
          });
        }
        rpc(e, t, { head: n = !1, count: r = null } = {}) {
          return this._initPostgRESTClient().rpc(e, t, { head: n, count: r });
        }
        removeAllSubscriptions() {
          return Ue(this, void 0, void 0, function* () {
            const e = this.getSubscriptions().slice(),
              t = e.map((e) => this.removeSubscription(e));
            return (yield Promise.all(t)).map(({ error: t }, n) => ({
              data: { subscription: e[n] },
              error: t,
            }));
          });
        }
        removeSubscription(e) {
          return Ue(this, void 0, void 0, function* () {
            const { error: t } = yield this._closeSubscription(e),
              n = this.getSubscriptions(),
              r = n.filter((e) => e.isJoined()).length;
            return (
              0 === n.length && (yield this.realtime.disconnect()),
              { data: { openSubscriptions: r }, error: t }
            );
          });
        }
        _closeSubscription(e) {
          return Ue(this, void 0, void 0, function* () {
            let t = null;
            if (!e.isClosed()) {
              const { error: n } = yield this._unsubscribeSubscription(e);
              t = n;
            }
            return this.realtime.remove(e), { error: t };
          });
        }
        _unsubscribeSubscription(e) {
          return new Promise((t) => {
            e.unsubscribe()
              .receive("ok", () => t({ error: null }))
              .receive("error", (e) => t({ error: e }))
              .receive("timeout", () => t({ error: new Error("timed out") }));
          });
        }
        getSubscriptions() {
          return this.realtime.channels;
        }
        _initSupabaseAuthClient({
          autoRefreshToken: e,
          persistSession: t,
          detectSessionInUrl: n,
          localStorage: r,
          headers: i,
          fetch: o,
          cookieOptions: s,
          multiTab: a,
        }) {
          const c = {
            Authorization: `Bearer ${this.supabaseKey}`,
            apikey: `${this.supabaseKey}`,
          };
          return new Y({
            url: this.authUrl,
            headers: Object.assign(Object.assign({}, i), c),
            autoRefreshToken: e,
            persistSession: t,
            detectSessionInUrl: n,
            localStorage: r,
            fetch: o,
            cookieOptions: s,
            multiTab: a,
          });
        }
        _initRealtimeClient(e) {
          return new fe(
            this.realtimeUrl,
            Object.assign(Object.assign({}, e), {
              params: Object.assign(
                Object.assign({}, null == e ? void 0 : e.params),
                { apikey: this.supabaseKey }
              ),
            })
          );
        }
        _initPostgRESTClient() {
          return new q(this.restUrl, {
            headers: this._getAuthHeaders(),
            schema: this.schema,
            fetch: this.fetch,
            throwOnError: this.shouldThrowOnError,
          });
        }
        _getAuthHeaders() {
          var e, t;
          const n = Object.assign({}, this.headers),
            r =
              null !==
                (t =
                  null === (e = this.auth.session()) || void 0 === e
                    ? void 0
                    : e.access_token) && void 0 !== t
                ? t
                : this.supabaseKey;
          return (
            (n.apikey = this.supabaseKey),
            (n.Authorization = n.Authorization || `Bearer ${r}`),
            n
          );
        }
        _listenForMultiTabEvents() {
          if (
            !this.multiTab ||
            "undefined" == typeof window ||
            !(null === window || void 0 === window
              ? void 0
              : window.addEventListener)
          )
            return null;
          try {
            return null === window || void 0 === window
              ? void 0
              : window.addEventListener("storage", (e) => {
                  var t, n, r;
                  if ("supabase.auth.token" === e.key) {
                    const i = JSON.parse(String(e.newValue)),
                      o =
                        null !==
                          (n =
                            null ===
                              (t = null == i ? void 0 : i.currentSession) ||
                            void 0 === t
                              ? void 0
                              : t.access_token) && void 0 !== n
                          ? n
                          : void 0,
                      s =
                        null === (r = this.auth.session()) || void 0 === r
                          ? void 0
                          : r.access_token;
                    o
                      ? !s && o
                        ? this._handleTokenChanged("SIGNED_IN", o, "STORAGE")
                        : s !== o &&
                          this._handleTokenChanged(
                            "TOKEN_REFRESHED",
                            o,
                            "STORAGE"
                          )
                      : this._handleTokenChanged("SIGNED_OUT", o, "STORAGE");
                  }
                });
          } catch (e) {
            return console.error("_listenForMultiTabEvents", e), null;
          }
        }
        _listenForAuthEvents() {
          let { data: e } = this.auth.onAuthStateChange((e, t) => {
            this._handleTokenChanged(
              e,
              null == t ? void 0 : t.access_token,
              "CLIENT"
            );
          });
          return e;
        }
        _handleTokenChanged(e, t, n) {
          ("TOKEN_REFRESHED" !== e && "SIGNED_IN" !== e) ||
          this.changedAccessToken === t
            ? ("SIGNED_OUT" !== e && "USER_DELETED" !== e) ||
              (this.realtime.setAuth(this.supabaseKey),
              "STORAGE" == n && this.auth.signOut())
            : (this.realtime.setAuth(t),
              "STORAGE" == n && this.auth.setAuth(t),
              (this.changedAccessToken = t));
        }
      }
      new (class {
        constructor() {
          (this.config = {
            endpoint: "https://HOSTNAME/v1",
            endpointRealtime: "",
            project: "",
            jwt: "",
            locale: "",
          }),
            (this.headers = {
              "x-sdk-version": "appwrite:web:9.0.1",
              "X-Appwrite-Response-Format": "0.15.0",
            }),
            (this.realtime = {
              socket: void 0,
              timeout: void 0,
              url: "",
              channels: new Set(),
              subscriptions: new Map(),
              subscriptionsCounter: 0,
              reconnect: !0,
              reconnectAttempts: 0,
              lastMessage: void 0,
              connect: () => {
                clearTimeout(this.realtime.timeout),
                  (this.realtime.timeout =
                    null === window || void 0 === window
                      ? void 0
                      : window.setTimeout(() => {
                          this.realtime.createSocket();
                        }, 50));
              },
              getTimeout: () => {
                switch (!0) {
                  case this.realtime.reconnectAttempts < 5:
                    return 1e3;
                  case this.realtime.reconnectAttempts < 15:
                    return 5e3;
                  case this.realtime.reconnectAttempts < 100:
                    return 1e4;
                  default:
                    return 6e4;
                }
              },
              createSocket: () => {
                var e, t;
                if (this.realtime.channels.size < 1) return;
                const n = new URLSearchParams();
                n.set("project", this.config.project),
                  this.realtime.channels.forEach((e) => {
                    n.append("channels[]", e);
                  });
                const r =
                  this.config.endpointRealtime + "/realtime?" + n.toString();
                (r !== this.realtime.url ||
                  !this.realtime.socket ||
                  (null === (e = this.realtime.socket) || void 0 === e
                    ? void 0
                    : e.readyState) > WebSocket.OPEN) &&
                  (this.realtime.socket &&
                    (null === (t = this.realtime.socket) || void 0 === t
                      ? void 0
                      : t.readyState) < WebSocket.CLOSING &&
                    ((this.realtime.reconnect = !1),
                    this.realtime.socket.close()),
                  (this.realtime.url = r),
                  (this.realtime.socket = new WebSocket(r)),
                  this.realtime.socket.addEventListener(
                    "message",
                    this.realtime.onMessage
                  ),
                  this.realtime.socket.addEventListener("open", (e) => {
                    this.realtime.reconnectAttempts = 0;
                  }),
                  this.realtime.socket.addEventListener("close", (e) => {
                    var t, n, r;
                    if (
                      !this.realtime.reconnect ||
                      ("error" ===
                        (null ===
                          (n =
                            null === (t = this.realtime) || void 0 === t
                              ? void 0
                              : t.lastMessage) || void 0 === n
                          ? void 0
                          : n.type) &&
                        1008 ===
                          (null === (r = this.realtime) || void 0 === r
                            ? void 0
                            : r.lastMessage.data
                          ).code)
                    )
                      return void (this.realtime.reconnect = !0);
                    const i = this.realtime.getTimeout();
                    console.error(
                      `Realtime got disconnected. Reconnect will be attempted in ${
                        i / 1e3
                      } seconds.`,
                      e.reason
                    ),
                      setTimeout(() => {
                        this.realtime.reconnectAttempts++,
                          this.realtime.createSocket();
                      }, i);
                  }));
              },
              onMessage: (e) => {
                var t, n;
                try {
                  const r = JSON.parse(e.data);
                  switch (((this.realtime.lastMessage = r), r.type)) {
                    case "connected":
                      const e = JSON.parse(
                          null !==
                            (t =
                              window.localStorage.getItem("cookieFallback")) &&
                            void 0 !== t
                            ? t
                            : "{}"
                        ),
                        i =
                          null == e
                            ? void 0
                            : e[`a_session_${this.config.project}`],
                        o = r.data;
                      i &&
                        !o.user &&
                        (null === (n = this.realtime.socket) ||
                          void 0 === n ||
                          n.send(
                            JSON.stringify({
                              type: "authentication",
                              data: { session: i },
                            })
                          ));
                      break;
                    case "event":
                      let s = r.data;
                      if (null == s ? void 0 : s.channels) {
                        if (
                          !s.channels.some((e) => this.realtime.channels.has(e))
                        )
                          return;
                        this.realtime.subscriptions.forEach((e) => {
                          s.channels.some((t) => e.channels.includes(t)) &&
                            setTimeout(() => e.callback(s));
                        });
                      }
                      break;
                    case "error":
                      throw r.data;
                  }
                } catch (e) {
                  console.error(e);
                }
              },
              cleanUp: (e) => {
                this.realtime.channels.forEach((t) => {
                  e.includes(t) &&
                    (Array.from(this.realtime.subscriptions).some(([e, n]) =>
                      n.channels.includes(t)
                    ) ||
                      this.realtime.channels.delete(t));
                });
              },
            });
        }
        setEndpoint(e) {
          return (
            (this.config.endpoint = e),
            (this.config.endpointRealtime =
              this.config.endpointRealtime ||
              this.config.endpoint
                .replace("https://", "wss://")
                .replace("http://", "ws://")),
            this
          );
        }
        setEndpointRealtime(e) {
          return (this.config.endpointRealtime = e), this;
        }
        setProject(e) {
          return (
            (this.headers["X-Appwrite-Project"] = e),
            (this.config.project = e),
            this
          );
        }
        setJWT(e) {
          return (
            (this.headers["X-Appwrite-JWT"] = e), (this.config.jwt = e), this
          );
        }
        setLocale(e) {
          return (
            (this.headers["X-Appwrite-Locale"] = e),
            (this.config.locale = e),
            this
          );
        }
        subscribe(e, t) {
          let n = "string" == typeof e ? [e] : e;
          n.forEach((e) => this.realtime.channels.add(e));
          const r = this.realtime.subscriptionsCounter++;
          return (
            this.realtime.subscriptions.set(r, { channels: n, callback: t }),
            this.realtime.connect(),
            () => {
              this.realtime.subscriptions.delete(r),
                this.realtime.cleanUp(n),
                this.realtime.connect();
            }
          );
        }
        call(n, i, o = {}, s = {}) {
          var a, c, l, A, d, u;
          return (
            (l = this),
            (A = void 0),
            (u = function* () {
              (n = n.toUpperCase()), (o = Object.assign({}, this.headers, o));
              let l = { method: n, headers: o, credentials: "include" };
              if (
                ("undefined" != typeof window &&
                  window.localStorage &&
                  (o["X-Fallback-Cookies"] =
                    null !==
                      (a = window.localStorage.getItem("cookieFallback")) &&
                    void 0 !== a
                      ? a
                      : ""),
                "GET" === n)
              )
                for (const [e, n] of Object.entries(t.flatten(s)))
                  i.searchParams.append(e, n);
              else
                switch (o["content-type"]) {
                  case "application/json":
                    l.body = JSON.stringify(s);
                    break;
                  case "multipart/form-data":
                    let e = new FormData();
                    for (const t in s)
                      Array.isArray(s[t])
                        ? s[t].forEach((n) => {
                            e.append(t + "[]", n);
                          })
                        : e.append(t, s[t]);
                    (l.body = e), delete o["content-type"];
                }
              try {
                let t = null;
                const n = yield (0, e.fetch)(i.toString(), l);
                if (
                  ((t = (
                    null === (c = n.headers.get("content-type")) || void 0 === c
                      ? void 0
                      : c.includes("application/json")
                  )
                    ? yield n.json()
                    : { message: yield n.text() }),
                  400 <= n.status)
                )
                  throw new r(
                    null == t ? void 0 : t.message,
                    n.status,
                    null == t ? void 0 : t.type,
                    t
                  );
                const o = n.headers.get("X-Fallback-Cookies");
                return (
                  "undefined" != typeof window &&
                    window.localStorage &&
                    o &&
                    (window.console.warn(
                      "Appwrite is using localStorage for session management. Increase your security by adding a custom domain as your API endpoint."
                    ),
                    window.localStorage.setItem("cookieFallback", o)),
                  t
                );
              } catch (e) {
                if (e instanceof r) throw e;
                throw new r(e.message);
              }
            }),
            new ((d = void 0) || (d = Promise))(function (e, t) {
              function n(e) {
                try {
                  i(u.next(e));
                } catch (e) {
                  t(e);
                }
              }
              function r(e) {
                try {
                  i(u.throw(e));
                } catch (e) {
                  t(e);
                }
              }
              function i(t) {
                var i;
                t.done
                  ? e(t.value)
                  : ((i = t.value),
                    i instanceof d
                      ? i
                      : new d(function (e) {
                          e(i);
                        })).then(n, r);
              }
              i((u = u.apply(l, A || [])).next());
            })
          );
        }
      })();
      const Pe = new Qe(
        "https://rsfcqodmucagrxohmkgx.supabase.co",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InJzZmNxb2RtdWNhZ3J4b2hta2d4Iiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTY2MDkyNjk0OSwiZXhwIjoxOTc2NTAyOTQ5fQ.8PZmvfHrTPVNheNjYHyJJS2jZC5EjCIlOkQK3t2Tvwc",
        void 0
      );
      Pe.auth.user()
        ? (document.getElementById("formie").classList.remove("hidden"),
          document.getElementById("notlogged").classList.add("hidden"))
        : (document.getElementById("formie").classList.add("hidden"),
          document.getElementById("notlogged").classList.remove("hidden"),
          (document.getElementById("lex").innerHTML = "Not Logged In"));
      var Re = [],
        Ye = decodeURIComponent(window.location.search),
        $e = (Ye = Ye.substring(1)).split("&"),
        Ge = $e[0].slice($e[0].indexOf("=") + 1),
        Ze = $e[1].slice($e[1].indexOf("=") + 1);
      function Fe(e) {
        return e
          .toLowerCase()
          .split(" ")
          .map(function (e) {
            return e[0].toUpperCase() + e.substr(1);
          })
          .join(" ");
      }
      function He(e) {
        var t = Fe(e.replaceAll("_", " ")),
          n = `<div class="col-span-6 sm:col-span-3 w-auto py-2 ">\n  <label for="${e}" class="block text-sm font-medium text-gray-700 pt-4 mb-1">${t}</label>\n  <input type="text" id="${e}" autocomplete="given-name" class=" focus:ring-blue-500  focus:border-blue-500 block w-full shadow-sm sm:text-sm border border-neutral-200 py-2 px-3 outline-none">\n</div>`;
        document.getElementById("elelist").insertAdjacentHTML("afterbegin", n),
          Re.push(e);
      }
      function We(e) {
        var t = Fe(e.replaceAll("_", " ")),
          n = `<div class="col-span-6 sm:col-span-3 w-auto py-2 ">\n  <label for="${e}" class="block text-sm font-medium text-gray-700 pt-4 mb-1">${t}</label>\n  <select for="${e}" id=${e}>\n  <option value="1">1</option>\n  <option value="2">2</option>\n  <option value="3">3</option>\n  </select>\n</div>`;
        document.getElementById("elelist").insertAdjacentHTML("afterbegin", n),
          Re.push(e);
      }
      function Je(e) {
        var t = Fe(e.replaceAll("_", " ")),
          n = `<div class="col-span-6 sm:col-span-3 w-auto py-2 ">\n  <label for="${e}" class="block text-sm font-medium text-gray-700 pt-4 mb-1">${t}</label>\n  <select for="${e}" id=${e}>\n  <option value="1">1</option>\n  <option value="2">2</option>\n  <option value="3">3</option>\n  <option value="4">4</option>\n  <option value="5">5</option>\n  <option value="6">6</option>\n  <option value="7">7</option>\n  <option value="8">8</option>\n  <option value="9">9</option>\n  <option value="10">10</option>\n  <option value="11">11</option>\n  <option value="12">12</option>\n  </select>\n</div>`;
        document.getElementById("elelist").insertAdjacentHTML("afterbegin", n),
          Re.push(e);
      }
      function qe(e) {
        var t = Fe(e.replaceAll("_", " ")),
          n = `<div class="col-span-6 sm:col-span-3 w-auto py-2 ">\n  <label for="${e}" class="block text-sm font-medium text-gray-700 pt-4 mb-1">${t}</label>\n  <select for="${e}" id=${e}>\n  <option value="A">A</option>\n  <option value="B">B</option>\n  <option value="C">C</option>\n  <option value="D">D</option>\n  <option value="E">E</option>\n  <option value="F">F</option>\n  <option value="G">G</option>\n  <option value="H">H</option>\n  <option value="I">I</option>\n  </select>\n</div>`;
        document.getElementById("elelist").insertAdjacentHTML("afterbegin", n),
          Re.push(e);
      }
      function Xe(e) {
        var t = Fe(e.replaceAll("_", " ")),
          n = `<div class="col-span-6 sm:col-span-3 w-auto py-2 ">\n  <label for="${e}" class="block text-sm font-medium text-gray-700 pt-4 mb-1">${t}</label>\n  <select for="${e}" id=${e}>\n  <option value="1">1</option>\n  <option value="2">2</option>\n  <option value="3">3</option>\n  <option value="4">4</option>\n  <option value="5">5</option>\n  <option value="6">6</option>\n  <option value="7">7</option>\n  <option value="8">8</option>\n  <option value="9">9</option>\n  <option value="10">10</option>\n  <option value="11">11</option>\n  <option value="12">12</option>\n  </select>\n</div>`;
        document.getElementById("elelist").insertAdjacentHTML("afterbegin", n),
          Re.push(e);
      }
      function Ve() {
        document.getElementById("formie").classList.add("hidden"),
          document.getElementById("notlogged").classList.remove("hidden"),
          (document.getElementById("lex").innerHTML = "Already Submitted");
      }
      !(async function () {
        const { data: e, error: t } = await Pe.from("Forms").select();
        (document.getElementById("title").innerHTML = e[Ge - 1].title),
          (document.getElementById("description").innerHTML =
            e[Ge - 1].description);
      })(),
        (async function () {
          const { data: e, error: t } = await Pe.from(Ze).select();
          for (let t in e)
            e[t].uid == window.localStorage.getItem("email") && Ve();
          var n = Object.keys(e[0]);
          console.log(n), n.pop(), n.reverse(), console.log(n);
          for (let e in n) {
            let t = n[e];
            switch (t) {
              case "level":
                We(t);
                break;
              case "month":
                Xe(t);
                break;
              case "class":
                Je(t);
                break;
              case "section":
                qe(t);
                break;
              default:
                He(t);
            }
          }
          document.getElementById("submit").addEventListener(
            "click",
            (e) => (
              e.preventDefault(),
              (async function () {
                const { data: e, error: t } = await Pe.from(Ze).select();
                var n = { uid: window.localStorage.getItem("email") },
                  r = Object.keys(e[0]);
                console.log(r), r.pop(), r.reverse();
                for (let e in r) n[r[e]] = document.getElementById(r[e]).value;
                const { d: i, e: o } = await Pe.from(Ze).insert(n);
                i &&
                  (Ve(),
                  y().alert("Submitted Successfully", null, y().Icons.Success));
              })(),
              !1
            )
          );
        })(),
        (window.addDate = function () {
          console.log("date added");
        }),
        (window.addVal = He);
    })();
})();
