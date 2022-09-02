(self.webpackChunktts = self.webpackChunktts || []).push([
  [98],
  {
    98: function (t, e) {
      var r = "undefined" != typeof self ? self : this,
        o = (function () {
          function t() {
            (this.fetch = !1), (this.DOMException = r.DOMException);
          }
          return (t.prototype = r), new t();
        })();
      !(function (t) {
        !(function (e) {
          var r = "URLSearchParams" in t,
            o = "Symbol" in t && "iterator" in Symbol,
            n =
              "FileReader" in t &&
              "Blob" in t &&
              (function () {
                try {
                  return new Blob(), !0;
                } catch (t) {
                  return !1;
                }
              })(),
            i = "FormData" in t,
            s = "ArrayBuffer" in t;
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
              h =
                ArrayBuffer.isView ||
                function (t) {
                  return t && a.indexOf(Object.prototype.toString.call(t)) > -1;
                };
          function u(t) {
            if (
              ("string" != typeof t && (t = String(t)),
              /[^a-z0-9\-#$%&'*+.^_`|~]/i.test(t))
            )
              throw new TypeError("Invalid character in header field name");
            return t.toLowerCase();
          }
          function f(t) {
            return "string" != typeof t && (t = String(t)), t;
          }
          function c(t) {
            var e = {
              next: function () {
                var e = t.shift();
                return { done: void 0 === e, value: e };
              },
            };
            return (
              o &&
                (e[Symbol.iterator] = function () {
                  return e;
                }),
              e
            );
          }
          function d(t) {
            (this.map = {}),
              t instanceof d
                ? t.forEach(function (t, e) {
                    this.append(e, t);
                  }, this)
                : Array.isArray(t)
                ? t.forEach(function (t) {
                    this.append(t[0], t[1]);
                  }, this)
                : t &&
                  Object.getOwnPropertyNames(t).forEach(function (e) {
                    this.append(e, t[e]);
                  }, this);
          }
          function p(t) {
            if (t.bodyUsed)
              return Promise.reject(new TypeError("Already read"));
            t.bodyUsed = !0;
          }
          function y(t) {
            return new Promise(function (e, r) {
              (t.onload = function () {
                e(t.result);
              }),
                (t.onerror = function () {
                  r(t.error);
                });
            });
          }
          function l(t) {
            var e = new FileReader(),
              r = y(e);
            return e.readAsArrayBuffer(t), r;
          }
          function b(t) {
            if (t.slice) return t.slice(0);
            var e = new Uint8Array(t.byteLength);
            return e.set(new Uint8Array(t)), e.buffer;
          }
          function m() {
            return (
              (this.bodyUsed = !1),
              (this._initBody = function (t) {
                var e;
                (this._bodyInit = t),
                  t
                    ? "string" == typeof t
                      ? (this._bodyText = t)
                      : n && Blob.prototype.isPrototypeOf(t)
                      ? (this._bodyBlob = t)
                      : i && FormData.prototype.isPrototypeOf(t)
                      ? (this._bodyFormData = t)
                      : r && URLSearchParams.prototype.isPrototypeOf(t)
                      ? (this._bodyText = t.toString())
                      : s && n && (e = t) && DataView.prototype.isPrototypeOf(e)
                      ? ((this._bodyArrayBuffer = b(t.buffer)),
                        (this._bodyInit = new Blob([this._bodyArrayBuffer])))
                      : s && (ArrayBuffer.prototype.isPrototypeOf(t) || h(t))
                      ? (this._bodyArrayBuffer = b(t))
                      : (this._bodyText = t = Object.prototype.toString.call(t))
                    : (this._bodyText = ""),
                  this.headers.get("content-type") ||
                    ("string" == typeof t
                      ? this.headers.set(
                          "content-type",
                          "text/plain;charset=UTF-8"
                        )
                      : this._bodyBlob && this._bodyBlob.type
                      ? this.headers.set("content-type", this._bodyBlob.type)
                      : r &&
                        URLSearchParams.prototype.isPrototypeOf(t) &&
                        this.headers.set(
                          "content-type",
                          "application/x-www-form-urlencoded;charset=UTF-8"
                        ));
              }),
              n &&
                ((this.blob = function () {
                  var t = p(this);
                  if (t) return t;
                  if (this._bodyBlob) return Promise.resolve(this._bodyBlob);
                  if (this._bodyArrayBuffer)
                    return Promise.resolve(new Blob([this._bodyArrayBuffer]));
                  if (this._bodyFormData)
                    throw new Error("could not read FormData body as blob");
                  return Promise.resolve(new Blob([this._bodyText]));
                }),
                (this.arrayBuffer = function () {
                  return this._bodyArrayBuffer
                    ? p(this) || Promise.resolve(this._bodyArrayBuffer)
                    : this.blob().then(l);
                })),
              (this.text = function () {
                var t,
                  e,
                  r,
                  o = p(this);
                if (o) return o;
                if (this._bodyBlob)
                  return (
                    (t = this._bodyBlob),
                    (r = y((e = new FileReader()))),
                    e.readAsText(t),
                    r
                  );
                if (this._bodyArrayBuffer)
                  return Promise.resolve(
                    (function (t) {
                      for (
                        var e = new Uint8Array(t),
                          r = new Array(e.length),
                          o = 0;
                        o < e.length;
                        o++
                      )
                        r[o] = String.fromCharCode(e[o]);
                      return r.join("");
                    })(this._bodyArrayBuffer)
                  );
                if (this._bodyFormData)
                  throw new Error("could not read FormData body as text");
                return Promise.resolve(this._bodyText);
              }),
              i &&
                (this.formData = function () {
                  return this.text().then(E);
                }),
              (this.json = function () {
                return this.text().then(JSON.parse);
              }),
              this
            );
          }
          (d.prototype.append = function (t, e) {
            (t = u(t)), (e = f(e));
            var r = this.map[t];
            this.map[t] = r ? r + ", " + e : e;
          }),
            (d.prototype.delete = function (t) {
              delete this.map[u(t)];
            }),
            (d.prototype.get = function (t) {
              return (t = u(t)), this.has(t) ? this.map[t] : null;
            }),
            (d.prototype.has = function (t) {
              return this.map.hasOwnProperty(u(t));
            }),
            (d.prototype.set = function (t, e) {
              this.map[u(t)] = f(e);
            }),
            (d.prototype.forEach = function (t, e) {
              for (var r in this.map)
                this.map.hasOwnProperty(r) && t.call(e, this.map[r], r, this);
            }),
            (d.prototype.keys = function () {
              var t = [];
              return (
                this.forEach(function (e, r) {
                  t.push(r);
                }),
                c(t)
              );
            }),
            (d.prototype.values = function () {
              var t = [];
              return (
                this.forEach(function (e) {
                  t.push(e);
                }),
                c(t)
              );
            }),
            (d.prototype.entries = function () {
              var t = [];
              return (
                this.forEach(function (e, r) {
                  t.push([r, e]);
                }),
                c(t)
              );
            }),
            o && (d.prototype[Symbol.iterator] = d.prototype.entries);
          var w = ["DELETE", "GET", "HEAD", "OPTIONS", "POST", "PUT"];
          function v(t, e) {
            var r,
              o,
              n = (e = e || {}).body;
            if (t instanceof v) {
              if (t.bodyUsed) throw new TypeError("Already read");
              (this.url = t.url),
                (this.credentials = t.credentials),
                e.headers || (this.headers = new d(t.headers)),
                (this.method = t.method),
                (this.mode = t.mode),
                (this.signal = t.signal),
                n ||
                  null == t._bodyInit ||
                  ((n = t._bodyInit), (t.bodyUsed = !0));
            } else this.url = String(t);
            if (
              ((this.credentials =
                e.credentials || this.credentials || "same-origin"),
              (!e.headers && this.headers) || (this.headers = new d(e.headers)),
              (this.method =
                ((o = (r = e.method || this.method || "GET").toUpperCase()),
                w.indexOf(o) > -1 ? o : r)),
              (this.mode = e.mode || this.mode || null),
              (this.signal = e.signal || this.signal),
              (this.referrer = null),
              ("GET" === this.method || "HEAD" === this.method) && n)
            )
              throw new TypeError("Body not allowed for GET or HEAD requests");
            this._initBody(n);
          }
          function E(t) {
            var e = new FormData();
            return (
              t
                .trim()
                .split("&")
                .forEach(function (t) {
                  if (t) {
                    var r = t.split("="),
                      o = r.shift().replace(/\+/g, " "),
                      n = r.join("=").replace(/\+/g, " ");
                    e.append(decodeURIComponent(o), decodeURIComponent(n));
                  }
                }),
              e
            );
          }
          function A(t, e) {
            e || (e = {}),
              (this.type = "default"),
              (this.status = void 0 === e.status ? 200 : e.status),
              (this.ok = this.status >= 200 && this.status < 300),
              (this.statusText = "statusText" in e ? e.statusText : "OK"),
              (this.headers = new d(e.headers)),
              (this.url = e.url || ""),
              this._initBody(t);
          }
          (v.prototype.clone = function () {
            return new v(this, { body: this._bodyInit });
          }),
            m.call(v.prototype),
            m.call(A.prototype),
            (A.prototype.clone = function () {
              return new A(this._bodyInit, {
                status: this.status,
                statusText: this.statusText,
                headers: new d(this.headers),
                url: this.url,
              });
            }),
            (A.error = function () {
              var t = new A(null, { status: 0, statusText: "" });
              return (t.type = "error"), t;
            });
          var _ = [301, 302, 303, 307, 308];
          (A.redirect = function (t, e) {
            if (-1 === _.indexOf(e))
              throw new RangeError("Invalid status code");
            return new A(null, { status: e, headers: { location: t } });
          }),
            (e.DOMException = t.DOMException);
          try {
            new e.DOMException();
          } catch (t) {
            (e.DOMException = function (t, e) {
              (this.message = t), (this.name = e);
              var r = Error(t);
              this.stack = r.stack;
            }),
              (e.DOMException.prototype = Object.create(Error.prototype)),
              (e.DOMException.prototype.constructor = e.DOMException);
          }
          function x(t, r) {
            return new Promise(function (o, i) {
              var s = new v(t, r);
              if (s.signal && s.signal.aborted)
                return i(new e.DOMException("Aborted", "AbortError"));
              var a = new XMLHttpRequest();
              function h() {
                a.abort();
              }
              (a.onload = function () {
                var t,
                  e,
                  r = {
                    status: a.status,
                    statusText: a.statusText,
                    headers:
                      ((t = a.getAllResponseHeaders() || ""),
                      (e = new d()),
                      t
                        .replace(/\r?\n[\t ]+/g, " ")
                        .split(/\r?\n/)
                        .forEach(function (t) {
                          var r = t.split(":"),
                            o = r.shift().trim();
                          if (o) {
                            var n = r.join(":").trim();
                            e.append(o, n);
                          }
                        }),
                      e),
                  };
                r.url =
                  "responseURL" in a
                    ? a.responseURL
                    : r.headers.get("X-Request-URL");
                var n = "response" in a ? a.response : a.responseText;
                o(new A(n, r));
              }),
                (a.onerror = function () {
                  i(new TypeError("Network request failed"));
                }),
                (a.ontimeout = function () {
                  i(new TypeError("Network request failed"));
                }),
                (a.onabort = function () {
                  i(new e.DOMException("Aborted", "AbortError"));
                }),
                a.open(s.method, s.url, !0),
                "include" === s.credentials
                  ? (a.withCredentials = !0)
                  : "omit" === s.credentials && (a.withCredentials = !1),
                "responseType" in a && n && (a.responseType = "blob"),
                s.headers.forEach(function (t, e) {
                  a.setRequestHeader(e, t);
                }),
                s.signal &&
                  (s.signal.addEventListener("abort", h),
                  (a.onreadystatechange = function () {
                    4 === a.readyState &&
                      s.signal.removeEventListener("abort", h);
                  })),
                a.send(void 0 === s._bodyInit ? null : s._bodyInit);
            });
          }
          (x.polyfill = !0),
            t.fetch ||
              ((t.fetch = x),
              (t.Headers = d),
              (t.Request = v),
              (t.Response = A)),
            (e.Headers = d),
            (e.Request = v),
            (e.Response = A),
            (e.fetch = x),
            Object.defineProperty(e, "__esModule", { value: !0 });
        })({});
      })(o),
        (o.fetch.ponyfill = !0),
        delete o.fetch.polyfill;
      var n = o;
      ((e = n.fetch).default = n.fetch),
        (e.fetch = n.fetch),
        (e.Headers = n.Headers),
        (e.Request = n.Request),
        (e.Response = n.Response),
        (t.exports = e);
    },
  },
]);
