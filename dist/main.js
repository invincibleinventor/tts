(() => {
  var e,
    n,
    t,
    r,
    i = {
      265: (e, n, t) => {
        "use strict";
        t.d(n, { Z: () => E });
        var r = t(537),
          i = t.n(r),
          o = t(645),
          s = t.n(o),
          a = t(667),
          c = t.n(a),
          A = new URL(t(909), t.b),
          l = new URL(t(133), t.b),
          d = new URL(t(601), t.b),
          u = new URL(t(686), t.b),
          h = s()(i()),
          g = c()(A),
          p = c()(l),
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
          var n = [];
          return (
            (n.toString = function () {
              return this.map(function (n) {
                var t = "",
                  r = void 0 !== n[5];
                return (
                  n[4] && (t += "@supports (".concat(n[4], ") {")),
                  n[2] && (t += "@media ".concat(n[2], " {")),
                  r &&
                    (t += "@layer".concat(
                      n[5].length > 0 ? " ".concat(n[5]) : "",
                      " {"
                    )),
                  (t += e(n)),
                  r && (t += "}"),
                  n[2] && (t += "}"),
                  n[4] && (t += "}"),
                  t
                );
              }).join("");
            }),
            (n.i = function (e, t, r, i, o) {
              "string" == typeof e && (e = [[null, e, void 0]]);
              var s = {};
              if (r)
                for (var a = 0; a < this.length; a++) {
                  var c = this[a][0];
                  null != c && (s[c] = !0);
                }
              for (var A = 0; A < e.length; A++) {
                var l = [].concat(e[A]);
                (r && s[l[0]]) ||
                  (void 0 !== o &&
                    (void 0 === l[5] ||
                      (l[1] = "@layer"
                        .concat(l[5].length > 0 ? " ".concat(l[5]) : "", " {")
                        .concat(l[1], "}")),
                    (l[5] = o)),
                  t &&
                    (l[2]
                      ? ((l[1] = "@media "
                          .concat(l[2], " {")
                          .concat(l[1], "}")),
                        (l[2] = t))
                      : (l[2] = t)),
                  i &&
                    (l[4]
                      ? ((l[1] = "@supports ("
                          .concat(l[4], ") {")
                          .concat(l[1], "}")),
                        (l[4] = i))
                      : (l[4] = "".concat(i))),
                  n.push(l));
              }
            }),
            n
          );
        };
      },
      667: (e) => {
        "use strict";
        e.exports = function (e, n) {
          return (
            n || (n = {}),
            e
              ? ((e = String(e.__esModule ? e.default : e)),
                /^['"].*['"]$/.test(e) && (e = e.slice(1, -1)),
                n.hash && (e += n.hash),
                /["'() \t\n]|(%20)/.test(e) || n.needQuotes
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
          var n = e[1],
            t = e[3];
          if (!t) return n;
          if ("function" == typeof btoa) {
            var r = btoa(unescape(encodeURIComponent(JSON.stringify(t)))),
              i =
                "sourceMappingURL=data:application/json;charset=utf-8;base64,".concat(
                  r
                ),
              o = "/*# ".concat(i, " */"),
              s = t.sources.map(function (e) {
                return "/*# sourceURL="
                  .concat(t.sourceRoot || "")
                  .concat(e, " */");
              });
            return [n].concat(s).concat([o]).join("\n");
          }
          return [n].join("\n");
        };
      },
      284: (e) => {
        var n = function () {
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
            return n();
          }
          try {
            return __global__ || n();
          } finally {
            delete Object.prototype.__global__;
          }
        })();
      },
      811: (e, n) => {
        "use strict";
        Object.defineProperty(n, "__esModule", { value: !0 });
        var t = (function () {
            function e(e, n) {
              for (var t = 0; t < n.length; t++) {
                var r = n[t];
                (r.enumerable = r.enumerable || !1),
                  (r.configurable = !0),
                  "value" in r && (r.writable = !0),
                  Object.defineProperty(e, r.key, r);
              }
            }
            return function (n, t, r) {
              return t && e(n.prototype, t), r && e(n, r), n;
            };
          })(),
          r = (function () {
            function e() {
              !(function (e, n) {
                if (!(e instanceof n))
                  throw new TypeError("Cannot call a class as a function");
              })(this, e);
            }
            return (
              t(e, [
                {
                  key: "when",
                  value: function (e) {
                    var n = this,
                      t =
                        arguments.length <= 1 || void 0 === arguments[1]
                          ? null
                          : arguments[1];
                    if (
                      ((this._eventListeners = this._eventListeners || {}),
                      (this._eventListeners[e] = this._eventListeners[e] || []),
                      !t)
                    )
                      return new Promise(function (t, r) {
                        (t._removeAfterCall = !0), n._eventListeners[e].push(t);
                      });
                    this._eventListeners[e].push(t);
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
                      var n =
                          (this._eventListeners && this._eventListeners[e]) ||
                          [],
                        t = arguments.length,
                        r = Array(t > 1 ? t - 1 : 0),
                        i = 1;
                      i < t;
                      i++
                    )
                      r[i - 1] = arguments[i];
                    var o = !0,
                      s = !1,
                      a = void 0;
                    try {
                      for (
                        var c, A = n[Symbol.iterator]();
                        !(o = (c = A.next()).done);
                        o = !0
                      ) {
                        var l = c.value;
                        l.apply(this, r);
                      }
                    } catch (e) {
                      (s = !0), (a = e);
                    } finally {
                      try {
                        !o && A.return && A.return();
                      } finally {
                        if (s) throw a;
                      }
                    }
                    for (var d = 0; d < n.length; d++)
                      n[d]._removeAfterCall && n.splice(d--, 1);
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
        (n.default = r),
          (r.mixin = function (e) {
            for (var n in r.prototype)
              r.prototype.hasOwnProperty(n) && (e[n] = r.prototype[n]);
          }),
          (e.exports = n.default);
      },
      585: (e, n) => {
        "use strict";
        Object.defineProperty(n, "__esModule", { value: !0 }),
          (n.default = {
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
          (e.exports = n.default);
      },
      625: (e, n, t) => {
        "use strict";
        Object.defineProperty(n, "__esModule", { value: !0 });
        var r = (function () {
            function e(e, n) {
              for (var t = 0; t < n.length; t++) {
                var r = n[t];
                (r.enumerable = r.enumerable || !1),
                  (r.configurable = !0),
                  "value" in r && (r.writable = !0),
                  Object.defineProperty(e, r.key, r);
              }
            }
            return function (n, t, r) {
              return t && e(n.prototype, t), r && e(n, r), n;
            };
          })(),
          i = a(t(929)),
          o = a(t(811)),
          s = a(t(585));
        function a(e) {
          return e && e.__esModule ? e : { default: e };
        }
        function c(e, n) {
          if (!(e instanceof n))
            throw new TypeError("Cannot call a class as a function");
        }
        function A(e, n) {
          if (!e)
            throw new ReferenceError(
              "this hasn't been initialised - super() hasn't been called"
            );
          return !n || ("object" != typeof n && "function" != typeof n) ? e : n;
        }
        var l = (function (e) {
          function n() {
            var e =
                arguments.length <= 0 || void 0 === arguments[0]
                  ? ""
                  : arguments[0],
              t =
                arguments.length <= 1 || void 0 === arguments[1]
                  ? ""
                  : arguments[1];
            c(this, n);
            var r = A(this, Object.getPrototypeOf(n).call(this));
            return (
              (r.elems = {}),
              (r.title = t),
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
            (function (e, n) {
              if ("function" != typeof n && null !== n)
                throw new TypeError(
                  "Super expression must either be null or a function, not " +
                    typeof n
                );
              (e.prototype = Object.create(n && n.prototype, {
                constructor: {
                  value: e,
                  enumerable: !1,
                  writable: !0,
                  configurable: !0,
                },
              })),
                n &&
                  (Object.setPrototypeOf
                    ? Object.setPrototypeOf(e, n)
                    : (e.__proto__ = n));
            })(n, e),
            r(n, null, [
              {
                key: "alert",
                value: function (e, t, r) {
                  var i =
                    arguments.length <= 3 || void 0 === arguments[3]
                      ? "Close"
                      : arguments[3];
                  if ("undefined" == typeof window)
                    return Promise.resolve(console.log("Alert: " + e));
                  var o = new n(e, t);
                  return (
                    o.addButton(i, null),
                    !1 !== r && o.setIcon(r || n.Icons.Information),
                    o.show()
                  );
                },
              },
              {
                key: "confirm",
                value: function (e, t, r) {
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
                  var s = new n(e, t);
                  return (
                    s.addButton(i, !0),
                    s.addButton(o, !1),
                    !1 !== r && s.setIcon(r || n.Icons.Question),
                    s.show()
                  );
                },
              },
              {
                key: "prompt",
                value: function (e, t, r, i, o) {
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
                  var c = new n(e, i);
                  return (
                    c.addButton(s, !0, "default"),
                    c.addButton(a, !1, "cancel"),
                    !1 !== o && c.setIcon(o || n.Icons.Question),
                    c.addTextField(t, null, r),
                    c.show().then(function (e) {
                      return c.cancelled ? null : c.getTextFieldValue(0);
                    })
                  );
                },
              },
              {
                key: "loader",
                value: function (e, t) {
                  if ("undefined" == typeof window)
                    return Promise.resolve(console.log("Loading: " + e));
                  var r = new n(e);
                  return (r.cancelable = t), r.show();
                },
              },
            ]),
            r(n, [
              {
                key: "setIcon",
                value: function (e) {
                  this.iconURL = e;
                },
              },
              {
                key: "addButton",
                value: function (e, n, t) {
                  var r = this;
                  return new Promise(function (i, o) {
                    r.buttons.push({
                      text: e,
                      value: void 0 === n ? e : n,
                      type: t || (0 == r.buttons.length ? "default" : "normal"),
                      callback: i,
                    });
                  });
                },
              },
              {
                key: "addTextField",
                value: function (e, n, t) {
                  this.textFields.push({
                    value: e || "",
                    type: n || "text",
                    placeholder: t || "",
                  });
                },
              },
              {
                key: "getTextFieldValue",
                value: function (e) {
                  var n = this.textFields[e];
                  return n.elem ? n.elem.value : n.value;
                },
              },
              {
                key: "show",
                value: function () {
                  var e = this;
                  return (
                    n.popupQueue.add(this).then(function () {
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
                      n.popupQueue.remove(this),
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
                      this.textFields.forEach(function (n, t) {
                        (n.elem = document.createElement("input")),
                          (n.elem.style.cssText =
                            "display: block; width: 90%; min-width: 250px; padding: 5px 0px; margin: 10px auto; background-color: #FFF; border: 1px solid #EEE; border-radius: 5px; text-align: center; font-family: Helvetica, Arial; font-size: 15px; color: #222; "),
                          (n.elem.value = n.value),
                          (n.elem.placeholder = n.placeholder),
                          (n.elem.type = n.type),
                          e.elems.textFields.appendChild(n.elem),
                          n.elem.addEventListener("keypress", function (n) {
                            13 == n.keyCode &&
                              (t + 1 >= e.textFields.length
                                ? e.dismiss("enter-pressed")
                                : e.textFields[t + 1].elem.focus());
                          });
                      }),
                      this.textFields[0].elem.focus()),
                    this.buttons.length > 0 &&
                      ((this.elems.buttons = document.createElement("div")),
                      (this.elems.buttons.style.cssText =
                        "display: block; display: flex; justify-content: space-around; align-items: center; text-align: right; border-top: 1px solid #EEE; margin-top: 10px; "),
                      this.elems.window.appendChild(this.elems.buttons),
                      this.buttons.forEach(function (n) {
                        var t = document.createElement("div");
                        (t.style.cssText =
                          "display: inline-block; font-family: Helvetica, Arial; font-size: 15px; font-weight: 200; color: #08F; padding: 10px 20px; padding-bottom: 0px; cursor: pointer; "),
                          (t.innerText = n.text),
                          e.elems.buttons.appendChild(t),
                          e.addTouchHandler(t, function () {
                            n.callback && n.callback(n.value),
                              "cancel" == n.type && (e.cancelled = !0),
                              e.dismiss(n.value);
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
                value: function (e, n) {
                  var t = function (t) {
                    "input" != t.target.nodeName.toLowerCase() &&
                      t.preventDefault(),
                      t.target == e && n();
                  };
                  this.elems.container.addEventListener("mousedown", t, !0),
                    this.elems.container.addEventListener("touchstart", t, !0);
                },
              },
              {
                key: "handleEvent",
                value: function (e) {
                  if (13 == e.keyCode) {
                    for (var n = 0; n < this.buttons.length; n++)
                      if ("default" == this.buttons[n].type)
                        return (
                          this.dismiss(this.buttons[n].value),
                          e.preventDefault(),
                          void (
                            this.buttons[n].callback &&
                            this.buttons[n].callback(this.result)
                          )
                        );
                    return (this.cancelled = !0), void this.dismiss();
                  }
                  if (27 == e.keyCode) {
                    if (!this.cancelable) return;
                    for (
                      this.cancelled = !0, this.result = null, n = 0;
                      n < this.buttons.length;
                      n++
                    )
                      if ("cancel" == this.buttons[n].type)
                        return (
                          this.dismiss(this.buttons[n].value),
                          e.preventDefault(),
                          void (
                            this.buttons[n].callback &&
                            this.buttons[n].callback(this.result)
                          )
                        );
                    return (this.cancelled = !0), void this.dismiss();
                  }
                },
              },
            ]),
            n
          );
        })(o.default);
        (n.default = l),
          (l.Icons = s.default),
          (l.popupQueue = new i.default()),
          (l.Queue = i.default),
          (l.EventSource = o.default),
          (e.exports = n.default);
      },
      929: (e, n, t) => {
        "use strict";
        Object.defineProperty(n, "__esModule", { value: !0 });
        var r,
          i = (function () {
            function e(e, n) {
              for (var t = 0; t < n.length; t++) {
                var r = n[t];
                (r.enumerable = r.enumerable || !1),
                  (r.configurable = !0),
                  "value" in r && (r.writable = !0),
                  Object.defineProperty(e, r.key, r);
              }
            }
            return function (n, t, r) {
              return t && e(n.prototype, t), r && e(n, r), n;
            };
          })(),
          o = (function (e) {
            function n() {
              !(function (e, n) {
                if (!(e instanceof n))
                  throw new TypeError("Cannot call a class as a function");
              })(this, n);
              var e = (function (e, n) {
                if (!e)
                  throw new ReferenceError(
                    "this hasn't been initialised - super() hasn't been called"
                  );
                return !n || ("object" != typeof n && "function" != typeof n)
                  ? e
                  : n;
              })(this, Object.getPrototypeOf(n).call(this));
              return (e.items = []), (e.current = null), e;
            }
            return (
              (function (e, n) {
                if ("function" != typeof n && null !== n)
                  throw new TypeError(
                    "Super expression must either be null or a function, not " +
                      typeof n
                  );
                (e.prototype = Object.create(n && n.prototype, {
                  constructor: {
                    value: e,
                    enumerable: !1,
                    writable: !0,
                    configurable: !0,
                  },
                })),
                  n &&
                    (Object.setPrototypeOf
                      ? Object.setPrototypeOf(e, n)
                      : (e.__proto__ = n));
              })(n, e),
              i(n, [
                {
                  key: "add",
                  value: function (e) {
                    var n = this;
                    return new Promise(function (t, r) {
                      n.items.push({ item: e, activateHandler: t }),
                        n.emit("added", e),
                        setTimeout(n.checkActivated.bind(n), 1);
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
                    for (var n = 0; n < this.items.length; n++)
                      this.items[n].item == e && this.items.splice(n--, 1);
                    this.emit("removed", e),
                      this.current &&
                        this.current.item == e &&
                        (this.current = null),
                      setTimeout(this.checkActivated.bind(this), 1);
                  },
                },
              ]),
              n
            );
          })(((r = t(811)) && r.__esModule ? r : { default: r }).default);
        (n.default = o), (e.exports = n.default);
      },
      379: (e) => {
        "use strict";
        var n = [];
        function t(e) {
          for (var t = -1, r = 0; r < n.length; r++)
            if (n[r].identifier === e) {
              t = r;
              break;
            }
          return t;
        }
        function r(e, r) {
          for (var o = {}, s = [], a = 0; a < e.length; a++) {
            var c = e[a],
              A = r.base ? c[0] + r.base : c[0],
              l = o[A] || 0,
              d = "".concat(A, " ").concat(l);
            o[A] = l + 1;
            var u = t(d),
              h = {
                css: c[1],
                media: c[2],
                sourceMap: c[3],
                supports: c[4],
                layer: c[5],
              };
            if (-1 !== u) n[u].references++, n[u].updater(h);
            else {
              var g = i(h, r);
              (r.byIndex = a),
                n.splice(a, 0, { identifier: d, updater: g, references: 1 });
            }
            s.push(d);
          }
          return s;
        }
        function i(e, n) {
          var t = n.domAPI(n);
          return (
            t.update(e),
            function (n) {
              if (n) {
                if (
                  n.css === e.css &&
                  n.media === e.media &&
                  n.sourceMap === e.sourceMap &&
                  n.supports === e.supports &&
                  n.layer === e.layer
                )
                  return;
                t.update((e = n));
              } else t.remove();
            }
          );
        }
        e.exports = function (e, i) {
          var o = r((e = e || []), (i = i || {}));
          return function (e) {
            e = e || [];
            for (var s = 0; s < o.length; s++) {
              var a = t(o[s]);
              n[a].references--;
            }
            for (var c = r(e, i), A = 0; A < o.length; A++) {
              var l = t(o[A]);
              0 === n[l].references && (n[l].updater(), n.splice(l, 1));
            }
            o = c;
          };
        };
      },
      569: (e) => {
        "use strict";
        var n = {};
        e.exports = function (e, t) {
          var r = (function (e) {
            if (void 0 === n[e]) {
              var t = document.querySelector(e);
              if (
                window.HTMLIFrameElement &&
                t instanceof window.HTMLIFrameElement
              )
                try {
                  t = t.contentDocument.head;
                } catch (e) {
                  t = null;
                }
              n[e] = t;
            }
            return n[e];
          })(e);
          if (!r)
            throw new Error(
              "Couldn't find a style target. This probably means that the value for the 'insert' parameter is invalid."
            );
          r.appendChild(t);
        };
      },
      216: (e) => {
        "use strict";
        e.exports = function (e) {
          var n = document.createElement("style");
          return e.setAttributes(n, e.attributes), e.insert(n, e.options), n;
        };
      },
      565: (e, n, t) => {
        "use strict";
        e.exports = function (e) {
          var n = t.nc;
          n && e.setAttribute("nonce", n);
        };
      },
      795: (e) => {
        "use strict";
        e.exports = function (e) {
          var n = e.insertStyleElement(e);
          return {
            update: function (t) {
              !(function (e, n, t) {
                var r = "";
                t.supports && (r += "@supports (".concat(t.supports, ") {")),
                  t.media && (r += "@media ".concat(t.media, " {"));
                var i = void 0 !== t.layer;
                i &&
                  (r += "@layer".concat(
                    t.layer.length > 0 ? " ".concat(t.layer) : "",
                    " {"
                  )),
                  (r += t.css),
                  i && (r += "}"),
                  t.media && (r += "}"),
                  t.supports && (r += "}");
                var o = t.sourceMap;
                o &&
                  "undefined" != typeof btoa &&
                  (r +=
                    "\n/*# sourceMappingURL=data:application/json;base64,".concat(
                      btoa(unescape(encodeURIComponent(JSON.stringify(o)))),
                      " */"
                    )),
                  n.styleTagTransform(r, e, n.options);
              })(n, e, t);
            },
            remove: function () {
              !(function (e) {
                if (null === e.parentNode) return !1;
                e.parentNode.removeChild(e);
              })(n);
            },
          };
        };
      },
      589: (e) => {
        "use strict";
        e.exports = function (e, n) {
          if (n.styleSheet) n.styleSheet.cssText = e;
          else {
            for (; n.firstChild; ) n.removeChild(n.firstChild);
            n.appendChild(document.createTextNode(e));
          }
        };
      },
      840: (e, n, t) => {
        var r;
        if ("object" == typeof globalThis) r = globalThis;
        else
          try {
            r = t(284);
          } catch (e) {
          } finally {
            if ((r || "undefined" == typeof window || (r = window), !r))
              throw new Error("Could not determine global this");
          }
        var i = r.WebSocket || r.MozWebSocket,
          o = t(387);
        function s(e, n) {
          return n ? new i(e, n) : new i(e);
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
      387: (e, n, t) => {
        e.exports = t(794).version;
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
    var n = o[e];
    if (void 0 !== n) return n.exports;
    var t = (o[e] = { id: e, exports: {} });
    return i[e].call(t.exports, t, t.exports, s), t.exports;
  }
  (s.m = i),
    (s.n = (e) => {
      var n = e && e.__esModule ? () => e.default : () => e;
      return s.d(n, { a: n }), n;
    }),
    (n = Object.getPrototypeOf
      ? (e) => Object.getPrototypeOf(e)
      : (e) => e.__proto__),
    (s.t = function (t, r) {
      if ((1 & r && (t = this(t)), 8 & r)) return t;
      if ("object" == typeof t && t) {
        if (4 & r && t.__esModule) return t;
        if (16 & r && "function" == typeof t.then) return t;
      }
      var i = Object.create(null);
      s.r(i);
      var o = {};
      e = e || [null, n({}), n([]), n(n)];
      for (var a = 2 & r && t; "object" == typeof a && !~e.indexOf(a); a = n(a))
        Object.getOwnPropertyNames(a).forEach((e) => (o[e] = () => t[e]));
      return (o.default = () => t), s.d(i, o), i;
    }),
    (s.d = (e, n) => {
      for (var t in n)
        s.o(n, t) &&
          !s.o(e, t) &&
          Object.defineProperty(e, t, { enumerable: !0, get: n[t] });
    }),
    (s.f = {}),
    (s.e = (e) =>
      Promise.all(Object.keys(s.f).reduce((n, t) => (s.f[t](e, n), n), []))),
    (s.u = (e) => e + ".js"),
    (s.g = (function () {
      if ("object" == typeof globalThis) return globalThis;
      try {
        return this || new Function("return this")();
      } catch (e) {
        if ("object" == typeof window) return window;
      }
    })()),
    (s.o = (e, n) => Object.prototype.hasOwnProperty.call(e, n)),
    (t = {}),
    (r = "tts:"),
    (s.l = (e, n, i, o) => {
      if (t[e]) t[e].push(n);
      else {
        var a, c;
        if (void 0 !== i)
          for (
            var A = document.getElementsByTagName("script"), l = 0;
            l < A.length;
            l++
          ) {
            var d = A[l];
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
          (t[e] = [n]);
        var u = (n, r) => {
            (a.onerror = a.onload = null), clearTimeout(h);
            var i = t[e];
            if (
              (delete t[e],
              a.parentNode && a.parentNode.removeChild(a),
              i && i.forEach((e) => e(r)),
              n)
            )
              return n(r);
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
      var n = s.g.document;
      if (!e && n && (n.currentScript && (e = n.currentScript.src), !e)) {
        var t = n.getElementsByTagName("script");
        t.length && (e = t[t.length - 1].src);
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
      var e = { 179: 0 };
      s.f.j = (n, t) => {
        var r = s.o(e, n) ? e[n] : void 0;
        if (0 !== r)
          if (r) t.push(r[2]);
          else {
            var i = new Promise((t, i) => (r = e[n] = [t, i]));
            t.push((r[2] = i));
            var o = s.p + s.u(n),
              a = new Error();
            s.l(
              o,
              (t) => {
                if (s.o(e, n) && (0 !== (r = e[n]) && (e[n] = void 0), r)) {
                  var i = t && ("load" === t.type ? "missing" : t.type),
                    o = t && t.target && t.target.src;
                  (a.message =
                    "Loading chunk " + n + " failed.\n(" + i + ": " + o + ")"),
                    (a.name = "ChunkLoadError"),
                    (a.type = i),
                    (a.request = o),
                    r[1](a);
                }
              },
              "chunk-" + n,
              n
            );
          }
      };
      var n = (n, t) => {
          var r,
            i,
            [o, a, c] = t,
            A = 0;
          if (o.some((n) => 0 !== e[n])) {
            for (r in a) s.o(a, r) && (s.m[r] = a[r]);
            c && c(s);
          }
          for (n && n(t); A < o.length; A++)
            (i = o[A]), s.o(e, i) && e[i] && e[i][0](), (e[i] = 0);
        },
        t = (self.webpackChunktts = self.webpackChunktts || []);
      t.forEach(n.bind(null, 0)), (t.push = n.bind(null, t.push.bind(t)));
    })(),
    (s.nc = void 0),
    (() => {
      "use strict";
      var e = s(379),
        n = s.n(e),
        t = s(795),
        r = s.n(t),
        i = s(569),
        o = s.n(i),
        a = s(565),
        c = s.n(a),
        A = s(216),
        l = s.n(A),
        d = s(589),
        u = s.n(d),
        h = s(265),
        g = {};
      (g.styleTagTransform = u()),
        (g.setAttributes = c()),
        (g.insert = o().bind(null, "head")),
        (g.domAPI = r()),
        (g.insertStyleElement = l()),
        n()(h.Z, g),
        h.Z && h.Z.locals && h.Z.locals;
      var p = s(625),
        m = s.n(p);
      const w = { "X-Client-Info": "supabase-js/1.35.6" },
        E = "Request Failed",
        f = "supabase.auth.token",
        C = {
          name: "sb",
          lifetime: 28800,
          domain: "",
          path: "/",
          sameSite: "lax",
        };
      var b = function (e, n, t, r) {
        return new (t || (t = Promise))(function (i, o) {
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
            var n;
            e.done
              ? i(e.value)
              : ((n = e.value),
                n instanceof t
                  ? n
                  : new t(function (e) {
                      e(n);
                    })).then(s, a);
          }
          c((r = r.apply(e, n || [])).next());
        });
      };
      const y = (e) =>
        e.msg ||
        e.message ||
        e.error_description ||
        e.error ||
        JSON.stringify(e);
      function M(e, n, t, r, i) {
        return b(this, void 0, void 0, function* () {
          return new Promise((o, s) => {
            e(
              t,
              ((e, n, t) => {
                const r = {
                  method: e,
                  headers: (null == n ? void 0 : n.headers) || {},
                };
                return (
                  "GET" === e ||
                    ((r.headers = Object.assign(
                      { "Content-Type": "text/plain;charset=UTF-8" },
                      null == n ? void 0 : n.headers
                    )),
                    (r.body = JSON.stringify(t))),
                  r
                );
              })(n, r, i)
            )
              .then((e) => {
                if (!e.ok) throw e;
                return (null == r ? void 0 : r.noResolveJson) ? o : e.json();
              })
              .then((e) => o(e))
              .catch((e) =>
                ((e, n) =>
                  (null == e ? void 0 : e.status)
                    ? "function" != typeof e.json
                      ? n(e)
                      : void e
                          .json()
                          .then((t) =>
                            n({
                              message: y(t),
                              status: (null == e ? void 0 : e.status) || 500,
                            })
                          )
                    : n({ message: E }))(e, s)
              );
          });
        });
      }
      function B(e, n, t) {
        return b(this, void 0, void 0, function* () {
          return M(e, "GET", n, t);
        });
      }
      function x(e, n, t, r) {
        return b(this, void 0, void 0, function* () {
          return M(e, "POST", n, r, t);
        });
      }
      function N(e, n, t, r) {
        return b(this, void 0, void 0, function* () {
          return M(e, "PUT", n, r, t);
        });
      }
      function v(e, n, t) {
        const r = t.map((n) => {
            return (
              (t = n),
              (r = (function (e) {
                if (!e || !e.headers || !e.headers.host)
                  throw new Error('The "host" request header is not available');
                const n =
                  (e.headers.host.indexOf(":") > -1 &&
                    e.headers.host.split(":")[0]) ||
                  e.headers.host;
                return !(
                  ["localhost", "127.0.0.1"].indexOf(n) > -1 ||
                  n.endsWith(".local")
                );
              })(e)),
              (function (e, n, t) {
                const r = t || {},
                  i = encodeURIComponent,
                  o = /^[\u0009\u0020-\u007e\u0080-\u00ff]+$/;
                if ("function" != typeof i)
                  throw new TypeError("option encode is invalid");
                if (!o.test(e)) throw new TypeError("argument name is invalid");
                const s = i(n);
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
              })(t.name, t.value, {
                maxAge: t.maxAge,
                expires: new Date(Date.now() + 1e3 * t.maxAge),
                httpOnly: !0,
                secure: r,
                path: null !== (i = t.path) && void 0 !== i ? i : "/",
                domain: null !== (o = t.domain) && void 0 !== o ? o : "",
                sameSite: null !== (s = t.sameSite) && void 0 !== s ? s : "lax",
              })
            );
            var t, r, i, o, s;
          }),
          i = n.getHeader("Set-Cookie");
        return (
          i &&
            (i instanceof Array
              ? Array.prototype.push.apply(r, i)
              : "string" == typeof i && r.push(i)),
          r
        );
      }
      function I(e, n, t) {
        n.setHeader("Set-Cookie", v(e, n, t));
      }
      var D = function (e, n, t, r) {
        return new (t || (t = Promise))(function (i, o) {
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
            var n;
            e.done
              ? i(e.value)
              : ((n = e.value),
                n instanceof t
                  ? n
                  : new t(function (e) {
                      e(n);
                    })).then(s, a);
          }
          c((r = r.apply(e, n || [])).next());
        });
      };
      function j(e) {
        return Math.round(Date.now() / 1e3) + e;
      }
      const k = () => "undefined" != typeof window;
      function T(e, n) {
        var t;
        n ||
          (n =
            (null ===
              (t =
                null === window || void 0 === window
                  ? void 0
                  : window.location) || void 0 === t
              ? void 0
              : t.href) || ""),
          (e = e.replace(/[\[\]]/g, "\\$&"));
        const r = new RegExp("[?&#]" + e + "(=([^&#]*)|&|#|$)").exec(n);
        return r
          ? r[2]
            ? decodeURIComponent(r[2].replace(/\+/g, " "))
            : ""
          : null;
      }
      const z = (e) => {
        let n;
        return (
          (n =
            e ||
            ("undefined" == typeof fetch
              ? (...e) =>
                  D(void 0, void 0, void 0, function* () {
                    return yield (yield s
                      .e(98)
                      .then(s.t.bind(s, 98, 23))).fetch(...e);
                  })
              : fetch)),
          (...e) => n(...e)
        );
      };
      var O = function (e, n, t, r) {
        return new (t || (t = Promise))(function (i, o) {
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
            var n;
            e.done
              ? i(e.value)
              : ((n = e.value),
                n instanceof t
                  ? n
                  : new t(function (e) {
                      e(n);
                    })).then(s, a);
          }
          c((r = r.apply(e, n || [])).next());
        });
      };
      class L {
        constructor({
          url: e = "",
          headers: n = {},
          cookieOptions: t,
          fetch: r,
        }) {
          (this.url = e),
            (this.headers = n),
            (this.cookieOptions = Object.assign(Object.assign({}, C), t)),
            (this.fetch = z(r));
        }
        _createRequestHeaders(e) {
          const n = Object.assign({}, this.headers);
          return (n.Authorization = `Bearer ${e}`), n;
        }
        cookieName() {
          var e;
          return null !== (e = this.cookieOptions.name) && void 0 !== e
            ? e
            : "";
        }
        getUrlForProvider(e, n) {
          const t = [`provider=${encodeURIComponent(e)}`];
          if (
            ((null == n ? void 0 : n.redirectTo) &&
              t.push(`redirect_to=${encodeURIComponent(n.redirectTo)}`),
            (null == n ? void 0 : n.scopes) &&
              t.push(`scopes=${encodeURIComponent(n.scopes)}`),
            null == n ? void 0 : n.queryParams)
          ) {
            const e = new URLSearchParams(n.queryParams);
            t.push(`${e}`);
          }
          return `${this.url}/authorize?${t.join("&")}`;
        }
        signUpWithEmail(e, n, t = {}) {
          return O(this, void 0, void 0, function* () {
            try {
              const r = Object.assign({}, this.headers);
              let i = "";
              t.redirectTo &&
                (i = "?redirect_to=" + encodeURIComponent(t.redirectTo));
              const o = yield x(
                  this.fetch,
                  `${this.url}/signup${i}`,
                  {
                    email: e,
                    password: n,
                    data: t.data,
                    gotrue_meta_security: { captcha_token: t.captchaToken },
                  },
                  { headers: r }
                ),
                s = Object.assign({}, o);
              return (
                s.expires_in && (s.expires_at = j(o.expires_in)),
                { data: s, error: null }
              );
            } catch (e) {
              return { data: null, error: e };
            }
          });
        }
        signInWithEmail(e, n, t = {}) {
          return O(this, void 0, void 0, function* () {
            try {
              const r = Object.assign({}, this.headers);
              let i = "?grant_type=password";
              t.redirectTo &&
                (i += "&redirect_to=" + encodeURIComponent(t.redirectTo));
              const o = yield x(
                  this.fetch,
                  `${this.url}/token${i}`,
                  {
                    email: e,
                    password: n,
                    gotrue_meta_security: { captcha_token: t.captchaToken },
                  },
                  { headers: r }
                ),
                s = Object.assign({}, o);
              return (
                s.expires_in && (s.expires_at = j(o.expires_in)),
                { data: s, error: null }
              );
            } catch (e) {
              return { data: null, error: e };
            }
          });
        }
        signUpWithPhone(e, n, t = {}) {
          return O(this, void 0, void 0, function* () {
            try {
              const r = Object.assign({}, this.headers),
                i = yield x(
                  this.fetch,
                  `${this.url}/signup`,
                  {
                    phone: e,
                    password: n,
                    data: t.data,
                    gotrue_meta_security: { captcha_token: t.captchaToken },
                  },
                  { headers: r }
                ),
                o = Object.assign({}, i);
              return (
                o.expires_in && (o.expires_at = j(i.expires_in)),
                { data: o, error: null }
              );
            } catch (e) {
              return { data: null, error: e };
            }
          });
        }
        signInWithPhone(e, n, t = {}) {
          return O(this, void 0, void 0, function* () {
            try {
              const r = Object.assign({}, this.headers),
                i = "?grant_type=password",
                o = yield x(
                  this.fetch,
                  `${this.url}/token${i}`,
                  {
                    phone: e,
                    password: n,
                    gotrue_meta_security: { captcha_token: t.captchaToken },
                  },
                  { headers: r }
                ),
                s = Object.assign({}, o);
              return (
                s.expires_in && (s.expires_at = j(o.expires_in)),
                { data: s, error: null }
              );
            } catch (e) {
              return { data: null, error: e };
            }
          });
        }
        signInWithOpenIDConnect({
          id_token: e,
          nonce: n,
          client_id: t,
          issuer: r,
          provider: i,
        }) {
          return O(this, void 0, void 0, function* () {
            try {
              const o = Object.assign({}, this.headers),
                s = "?grant_type=id_token",
                a = yield x(
                  this.fetch,
                  `${this.url}/token${s}`,
                  {
                    id_token: e,
                    nonce: n,
                    client_id: t,
                    issuer: r,
                    provider: i,
                  },
                  { headers: o }
                ),
                c = Object.assign({}, a);
              return (
                c.expires_in && (c.expires_at = j(a.expires_in)),
                { data: c, error: null }
              );
            } catch (e) {
              return { data: null, error: e };
            }
          });
        }
        sendMagicLinkEmail(e, n = {}) {
          var t;
          return O(this, void 0, void 0, function* () {
            try {
              const r = Object.assign({}, this.headers);
              let i = "";
              n.redirectTo &&
                (i += "?redirect_to=" + encodeURIComponent(n.redirectTo));
              const o = null === (t = n.shouldCreateUser) || void 0 === t || t;
              return {
                data: yield x(
                  this.fetch,
                  `${this.url}/otp${i}`,
                  {
                    email: e,
                    create_user: o,
                    gotrue_meta_security: { captcha_token: n.captchaToken },
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
        sendMobileOTP(e, n = {}) {
          var t;
          return O(this, void 0, void 0, function* () {
            try {
              const r = null === (t = n.shouldCreateUser) || void 0 === t || t,
                i = Object.assign({}, this.headers);
              return {
                data: yield x(
                  this.fetch,
                  `${this.url}/otp`,
                  {
                    phone: e,
                    create_user: r,
                    gotrue_meta_security: { captcha_token: n.captchaToken },
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
          return O(this, void 0, void 0, function* () {
            try {
              return (
                yield x(
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
        verifyMobileOTP(e, n, t = {}) {
          return O(this, void 0, void 0, function* () {
            try {
              const r = Object.assign({}, this.headers),
                i = yield x(
                  this.fetch,
                  `${this.url}/verify`,
                  {
                    phone: e,
                    token: n,
                    type: "sms",
                    redirect_to: t.redirectTo,
                  },
                  { headers: r }
                ),
                o = Object.assign({}, i);
              return (
                o.expires_in && (o.expires_at = j(i.expires_in)),
                { data: o, error: null }
              );
            } catch (e) {
              return { data: null, error: e };
            }
          });
        }
        verifyOTP({ email: e, phone: n, token: t, type: r = "sms" }, i = {}) {
          return O(this, void 0, void 0, function* () {
            try {
              const o = Object.assign({}, this.headers),
                s = yield x(
                  this.fetch,
                  `${this.url}/verify`,
                  {
                    email: e,
                    phone: n,
                    token: t,
                    type: r,
                    redirect_to: i.redirectTo,
                  },
                  { headers: o }
                ),
                a = Object.assign({}, s);
              return (
                a.expires_in && (a.expires_at = j(s.expires_in)),
                { data: a, error: null }
              );
            } catch (e) {
              return { data: null, error: e };
            }
          });
        }
        inviteUserByEmail(e, n = {}) {
          return O(this, void 0, void 0, function* () {
            try {
              const t = Object.assign({}, this.headers);
              let r = "";
              return (
                n.redirectTo &&
                  (r += "?redirect_to=" + encodeURIComponent(n.redirectTo)),
                {
                  data: yield x(
                    this.fetch,
                    `${this.url}/invite${r}`,
                    { email: e, data: n.data },
                    { headers: t }
                  ),
                  error: null,
                }
              );
            } catch (e) {
              return { data: null, error: e };
            }
          });
        }
        resetPasswordForEmail(e, n = {}) {
          return O(this, void 0, void 0, function* () {
            try {
              const t = Object.assign({}, this.headers);
              let r = "";
              return (
                n.redirectTo &&
                  (r += "?redirect_to=" + encodeURIComponent(n.redirectTo)),
                {
                  data: yield x(
                    this.fetch,
                    `${this.url}/recover${r}`,
                    {
                      email: e,
                      gotrue_meta_security: { captcha_token: n.captchaToken },
                    },
                    { headers: t }
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
          return O(this, void 0, void 0, function* () {
            try {
              const n = yield x(
                  this.fetch,
                  `${this.url}/token?grant_type=refresh_token`,
                  { refresh_token: e },
                  { headers: this.headers }
                ),
                t = Object.assign({}, n);
              return (
                t.expires_in && (t.expires_at = j(n.expires_in)),
                { data: t, error: null }
              );
            } catch (e) {
              return { data: null, error: e };
            }
          });
        }
        setAuthCookie(e, n) {
          "POST" !== e.method &&
            (n.setHeader("Allow", "POST"),
            n.status(405).end("Method Not Allowed"));
          const { event: t, session: r } = e.body;
          if (!t) throw new Error("Auth event missing!");
          if ("SIGNED_IN" === t) {
            if (!r) throw new Error("Auth session missing!");
            I(
              e,
              n,
              [
                { key: "access-token", value: r.access_token },
                { key: "refresh-token", value: r.refresh_token },
              ].map((e) => {
                var n;
                return {
                  name: `${this.cookieName()}-${e.key}`,
                  value: e.value,
                  domain: this.cookieOptions.domain,
                  maxAge:
                    null !== (n = this.cookieOptions.lifetime) && void 0 !== n
                      ? n
                      : 0,
                  path: this.cookieOptions.path,
                  sameSite: this.cookieOptions.sameSite,
                };
              })
            );
          }
          "SIGNED_OUT" === t &&
            I(
              e,
              n,
              ["access-token", "refresh-token"].map((e) => ({
                name: `${this.cookieName()}-${e}`,
                value: "",
                maxAge: -1,
              }))
            ),
            n.status(200).json({});
        }
        deleteAuthCookie(e, n, { redirectTo: t = "/" }) {
          return (
            I(
              e,
              n,
              ["access-token", "refresh-token"].map((e) => ({
                name: `${this.cookieName()}-${e}`,
                value: "",
                maxAge: -1,
              }))
            ),
            n.redirect(307, t)
          );
        }
        getAuthCookieString(e, n) {
          "POST" !== e.method &&
            (n.setHeader("Allow", "POST"),
            n.status(405).end("Method Not Allowed"));
          const { event: t, session: r } = e.body;
          if (!t) throw new Error("Auth event missing!");
          if ("SIGNED_IN" === t) {
            if (!r) throw new Error("Auth session missing!");
            return v(
              e,
              n,
              [
                { key: "access-token", value: r.access_token },
                { key: "refresh-token", value: r.refresh_token },
              ].map((e) => {
                var n;
                return {
                  name: `${this.cookieName()}-${e.key}`,
                  value: e.value,
                  domain: this.cookieOptions.domain,
                  maxAge:
                    null !== (n = this.cookieOptions.lifetime) && void 0 !== n
                      ? n
                      : 0,
                  path: this.cookieOptions.path,
                  sameSite: this.cookieOptions.sameSite,
                };
              })
            );
          }
          return "SIGNED_OUT" === t
            ? v(
                e,
                n,
                ["access-token", "refresh-token"].map((e) => ({
                  name: `${this.cookieName()}-${e}`,
                  value: "",
                  maxAge: -1,
                }))
              )
            : n.getHeader("Set-Cookie");
        }
        generateLink(e, n, t = {}) {
          return O(this, void 0, void 0, function* () {
            try {
              return {
                data: yield x(
                  this.fetch,
                  `${this.url}/admin/generate_link`,
                  {
                    type: e,
                    email: n,
                    password: t.password,
                    data: t.data,
                    redirect_to: t.redirectTo,
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
          return O(this, void 0, void 0, function* () {
            try {
              const n = yield x(this.fetch, `${this.url}/admin/users`, e, {
                headers: this.headers,
              });
              return { user: n, data: n, error: null };
            } catch (e) {
              return { user: null, data: null, error: e };
            }
          });
        }
        listUsers() {
          return O(this, void 0, void 0, function* () {
            try {
              return {
                data: (yield B(this.fetch, `${this.url}/admin/users`, {
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
          return O(this, void 0, void 0, function* () {
            try {
              return {
                data: yield B(this.fetch, `${this.url}/admin/users/${e}`, {
                  headers: this.headers,
                }),
                error: null,
              };
            } catch (e) {
              return { data: null, error: e };
            }
          });
        }
        getUserByCookie(e, n) {
          return O(this, void 0, void 0, function* () {
            try {
              if (!e.cookies)
                throw new Error(
                  "Not able to parse cookies! When using Express make sure the cookie-parser middleware is in use!"
                );
              const t = e.cookies[`${this.cookieName()}-access-token`],
                r = e.cookies[`${this.cookieName()}-refresh-token`];
              if (!t) throw new Error("No cookie found!");
              const { user: i, error: o } = yield this.getUser(t);
              if (o) {
                if (!r) throw new Error("No refresh_token cookie found!");
                if (!n)
                  throw new Error(
                    "You need to pass the res object to automatically refresh the session!"
                  );
                const { data: t, error: i } = yield this.refreshAccessToken(r);
                if (i) throw i;
                if (t)
                  return (
                    I(
                      e,
                      n,
                      [
                        { key: "access-token", value: t.access_token },
                        { key: "refresh-token", value: t.refresh_token },
                      ].map((e) => {
                        var n;
                        return {
                          name: `${this.cookieName()}-${e.key}`,
                          value: e.value,
                          domain: this.cookieOptions.domain,
                          maxAge:
                            null !== (n = this.cookieOptions.lifetime) &&
                            void 0 !== n
                              ? n
                              : 0,
                          path: this.cookieOptions.path,
                          sameSite: this.cookieOptions.sameSite,
                        };
                      })
                    ),
                    {
                      token: t.access_token,
                      user: t.user,
                      data: t.user,
                      error: null,
                    }
                  );
              }
              return { token: t, user: i, data: i, error: null };
            } catch (e) {
              return { token: null, user: null, data: null, error: e };
            }
          });
        }
        updateUserById(e, n) {
          return O(this, void 0, void 0, function* () {
            try {
              const t = yield N(this.fetch, `${this.url}/admin/users/${e}`, n, {
                headers: this.headers,
              });
              return { user: t, data: t, error: null };
            } catch (e) {
              return { user: null, data: null, error: e };
            }
          });
        }
        deleteUser(e) {
          return O(this, void 0, void 0, function* () {
            try {
              const n = yield (function (e, n, t, r) {
                return b(this, void 0, void 0, function* () {
                  return M(e, "DELETE", n, r, t);
                });
              })(
                this.fetch,
                `${this.url}/admin/users/${e}`,
                {},
                { headers: this.headers }
              );
              return { user: n, data: n, error: null };
            } catch (e) {
              return { user: null, data: null, error: e };
            }
          });
        }
        getUser(e) {
          return O(this, void 0, void 0, function* () {
            try {
              const n = yield B(this.fetch, `${this.url}/user`, {
                headers: this._createRequestHeaders(e),
              });
              return { user: n, data: n, error: null };
            } catch (e) {
              return { user: null, data: null, error: e };
            }
          });
        }
        updateUser(e, n) {
          return O(this, void 0, void 0, function* () {
            try {
              const t = yield N(this.fetch, `${this.url}/user`, n, {
                headers: this._createRequestHeaders(e),
              });
              return { user: t, data: t, error: null };
            } catch (e) {
              return { user: null, data: null, error: e };
            }
          });
        }
      }
      var S = function (e, n, t, r) {
        return new (t || (t = Promise))(function (i, o) {
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
            var n;
            e.done
              ? i(e.value)
              : ((n = e.value),
                n instanceof t
                  ? n
                  : new t(function (e) {
                      e(n);
                    })).then(s, a);
          }
          c((r = r.apply(e, n || [])).next());
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
      const U = {
        url: "http://localhost:9999",
        autoRefreshToken: !0,
        persistSession: !0,
        detectSessionInUrl: !0,
        multiTab: !0,
        headers: { "X-Client-Info": "gotrue-js/1.22.22" },
      };
      class Q extends class {
        constructor(e) {
          (this.stateChangeEmitters = new Map()), (this.networkRetries = 0);
          const n = Object.assign(Object.assign({}, U), e);
          (this.currentUser = null),
            (this.currentSession = null),
            (this.autoRefreshToken = n.autoRefreshToken),
            (this.persistSession = n.persistSession),
            (this.multiTab = n.multiTab),
            (this.localStorage = n.localStorage || globalThis.localStorage),
            (this.api = new L({
              url: n.url,
              headers: n.headers,
              cookieOptions: n.cookieOptions,
              fetch: n.fetch,
            })),
            this._recoverSession(),
            this._recoverAndRefresh(),
            this._listenForMultiTabEvents(),
            this._handleVisibilityChange(),
            n.detectSessionInUrl &&
              k() &&
              T("access_token") &&
              this.getSessionFromUrl({ storeSession: !0 }).then(
                ({ error: e }) => {
                  if (e) throw new Error("Error getting session from URL.");
                }
              );
        }
        signUp({ email: e, password: n, phone: t }, r = {}) {
          return S(this, void 0, void 0, function* () {
            try {
              this._removeSession();
              const { data: i, error: o } =
                t && n
                  ? yield this.api.signUpWithPhone(t, n, {
                      data: r.data,
                      captchaToken: r.captchaToken,
                    })
                  : yield this.api.signUpWithEmail(e, n, {
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
            phone: n,
            password: t,
            refreshToken: r,
            provider: i,
            oidc: o,
          },
          s = {}
        ) {
          return S(this, void 0, void 0, function* () {
            try {
              if ((this._removeSession(), e && !t)) {
                const { error: n } = yield this.api.sendMagicLinkEmail(e, {
                  redirectTo: s.redirectTo,
                  shouldCreateUser: s.shouldCreateUser,
                  captchaToken: s.captchaToken,
                });
                return { user: null, session: null, error: n };
              }
              if (e && t)
                return this._handleEmailSignIn(e, t, {
                  redirectTo: s.redirectTo,
                  captchaToken: s.captchaToken,
                });
              if (n && !t) {
                const { error: e } = yield this.api.sendMobileOTP(n, {
                  shouldCreateUser: s.shouldCreateUser,
                  captchaToken: s.captchaToken,
                });
                return { user: null, session: null, error: e };
              }
              if (n && t) return this._handlePhoneSignIn(n, t);
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
        verifyOTP(e, n = {}) {
          return S(this, void 0, void 0, function* () {
            try {
              this._removeSession();
              const { data: t, error: r } = yield this.api.verifyOTP(e, n);
              if (r) throw r;
              if (!t) throw "An error occurred on token verification.";
              let i = null,
                o = null;
              return (
                t.access_token &&
                  ((i = t),
                  (o = i.user),
                  this._saveSession(i),
                  this._notifyAllSubscribers("SIGNED_IN")),
                t.id && (o = t),
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
          return S(this, void 0, void 0, function* () {
            try {
              if (
                !(null === (e = this.currentSession) || void 0 === e
                  ? void 0
                  : e.access_token)
              )
                throw new Error("Not logged in.");
              const { error: n } = yield this._callRefreshToken();
              if (n) throw n;
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
          var n;
          return S(this, void 0, void 0, function* () {
            try {
              if (
                !(null === (n = this.currentSession) || void 0 === n
                  ? void 0
                  : n.access_token)
              )
                throw new Error("Not logged in.");
              const { user: t, error: r } = yield this.api.updateUser(
                this.currentSession.access_token,
                e
              );
              if (r) throw r;
              if (!t) throw Error("Invalid user data.");
              const i = Object.assign(Object.assign({}, this.currentSession), {
                user: t,
              });
              return (
                this._saveSession(i),
                this._notifyAllSubscribers("USER_UPDATED"),
                { data: t, user: t, error: null }
              );
            } catch (e) {
              return { data: null, user: null, error: e };
            }
          });
        }
        setSession(e) {
          return S(this, void 0, void 0, function* () {
            try {
              if (!e) throw new Error("No current session.");
              const { data: n, error: t } = yield this.api.refreshAccessToken(
                e
              );
              return t
                ? { session: null, error: t }
                : (this._saveSession(n),
                  this._notifyAllSubscribers("SIGNED_IN"),
                  { session: n, error: null });
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
          return S(this, void 0, void 0, function* () {
            try {
              if (!k()) throw new Error("No browser detected.");
              const n = T("error_description");
              if (n) throw new Error(n);
              const t = T("provider_token"),
                r = T("access_token");
              if (!r) throw new Error("No access_token detected.");
              const i = T("expires_in");
              if (!i) throw new Error("No expires_in detected.");
              const o = T("refresh_token");
              if (!o) throw new Error("No refresh_token detected.");
              const s = T("token_type");
              if (!s) throw new Error("No token_type detected.");
              const a = Math.round(Date.now() / 1e3) + parseInt(i),
                { user: c, error: A } = yield this.api.getUser(r);
              if (A) throw A;
              const l = {
                provider_token: t,
                access_token: r,
                expires_in: parseInt(i),
                expires_at: a,
                refresh_token: o,
                token_type: s,
                user: c,
              };
              if (null == e ? void 0 : e.storeSession) {
                this._saveSession(l);
                const e = T("type");
                this._notifyAllSubscribers("SIGNED_IN"),
                  "recovery" === e &&
                    this._notifyAllSubscribers("PASSWORD_RECOVERY");
              }
              return (window.location.hash = ""), { data: l, error: null };
            } catch (e) {
              return { data: null, error: e };
            }
          });
        }
        signOut() {
          var e;
          return S(this, void 0, void 0, function* () {
            const n =
              null === (e = this.currentSession) || void 0 === e
                ? void 0
                : e.access_token;
            if (
              (this._removeSession(),
              this._notifyAllSubscribers("SIGNED_OUT"),
              n)
            ) {
              const { error: e } = yield this.api.signOut(n);
              if (e) return { error: e };
            }
            return { error: null };
          });
        }
        onAuthStateChange(e) {
          try {
            const n = "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(
                /[xy]/g,
                function (e) {
                  const n = (16 * Math.random()) | 0;
                  return ("x" == e ? n : (3 & n) | 8).toString(16);
                }
              ),
              t = {
                id: n,
                callback: e,
                unsubscribe: () => {
                  this.stateChangeEmitters.delete(n);
                },
              };
            return this.stateChangeEmitters.set(n, t), { data: t, error: null };
          } catch (e) {
            return { data: null, error: e };
          }
        }
        _handleEmailSignIn(e, n, t = {}) {
          var r, i;
          return S(this, void 0, void 0, function* () {
            try {
              const { data: o, error: s } = yield this.api.signInWithEmail(
                e,
                n,
                { redirectTo: t.redirectTo, captchaToken: t.captchaToken }
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
        _handlePhoneSignIn(e, n, t = {}) {
          var r;
          return S(this, void 0, void 0, function* () {
            try {
              const { data: i, error: o } = yield this.api.signInWithPhone(
                e,
                n,
                t
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
        _handleProviderSignIn(e, n = {}) {
          const t = this.api.getUrlForProvider(e, {
            redirectTo: n.redirectTo,
            scopes: n.scopes,
            queryParams: n.queryParams,
          });
          try {
            return (
              k() && (window.location.href = t),
              {
                provider: e,
                url: t,
                data: null,
                session: null,
                user: null,
                error: null,
              }
            );
          } catch (n) {
            return t
              ? {
                  provider: e,
                  url: t,
                  data: null,
                  session: null,
                  user: null,
                  error: null,
                }
              : { data: null, user: null, session: null, error: n };
          }
        }
        _handleOpenIDConnectSignIn({
          id_token: e,
          nonce: n,
          client_id: t,
          issuer: r,
          provider: i,
        }) {
          return S(this, void 0, void 0, function* () {
            if (e && n && ((t && r) || i))
              try {
                const { data: o, error: s } =
                  yield this.api.signInWithOpenIDConnect({
                    id_token: e,
                    nonce: n,
                    client_id: t,
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
            const e = ((e, n) => {
              const t =
                k() && (null == e ? void 0 : e.getItem("supabase.auth.token"));
              if (!t || "string" != typeof t) return null;
              try {
                return JSON.parse(t);
              } catch (e) {
                return t;
              }
            })(this.localStorage);
            if (!e) return null;
            const { currentSession: n, expiresAt: t } = e;
            t >= Math.round(Date.now() / 1e3) + 10 &&
              (null == n ? void 0 : n.user) &&
              (this._saveSession(n), this._notifyAllSubscribers("SIGNED_IN"));
          } catch (e) {
            console.log("error", e);
          }
        }
        _recoverAndRefresh() {
          return S(this, void 0, void 0, function* () {
            try {
              const n = yield ((e = this.localStorage),
              f,
              D(void 0, void 0, void 0, function* () {
                const n =
                  k() &&
                  (yield null == e ? void 0 : e.getItem("supabase.auth.token"));
                if (!n) return null;
                try {
                  return JSON.parse(n);
                } catch (e) {
                  return n;
                }
              }));
              if (!n) return null;
              const { currentSession: t, expiresAt: r } = n;
              if (r < Math.round(Date.now() / 1e3) + 10)
                if (this.autoRefreshToken && t.refresh_token) {
                  this.networkRetries++;
                  const { error: e } = yield this._callRefreshToken(
                    t.refresh_token
                  );
                  if (e) {
                    if (
                      (console.log(e.message),
                      e.message === E && this.networkRetries < 10)
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
                t
                  ? (this._saveSession(t),
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
          var n;
          return (
            void 0 === e &&
              (e =
                null === (n = this.currentSession) || void 0 === n
                  ? void 0
                  : n.refresh_token),
            S(this, void 0, void 0, function* () {
              try {
                if (!e) throw new Error("No current session.");
                const { data: n, error: t } = yield this.api.refreshAccessToken(
                  e
                );
                if (t) throw t;
                if (!n) throw Error("Invalid session data.");
                return (
                  this._saveSession(n),
                  this._notifyAllSubscribers("TOKEN_REFRESHED"),
                  this._notifyAllSubscribers("SIGNED_IN"),
                  { data: n, error: null }
                );
              } catch (e) {
                return { data: null, error: e };
              }
            })
          );
        }
        _notifyAllSubscribers(e) {
          this.stateChangeEmitters.forEach((n) =>
            n.callback(e, this.currentSession)
          );
        }
        _saveSession(e) {
          (this.currentSession = e), (this.currentUser = e.user);
          const n = e.expires_at;
          if (n) {
            const e = n - Math.round(Date.now() / 1e3),
              t = e > 10 ? 10 : 0.5;
            this._startAutoRefreshToken(1e3 * (e - t));
          }
          this.persistSession &&
            e.expires_at &&
            this._persistSession(this.currentSession);
        }
        _persistSession(e) {
          const n = { currentSession: e, expiresAt: e.expires_at };
          ((e, n, t) => {
            D(void 0, void 0, void 0, function* () {
              k() &&
                (yield null == e
                  ? void 0
                  : e.setItem("supabase.auth.token", JSON.stringify(t)));
            });
          })(this.localStorage, 0, n);
        }
        _removeSession() {
          return S(this, void 0, void 0, function* () {
            var e;
            (this.currentSession = null),
              (this.currentUser = null),
              this.refreshTokenTimer && clearTimeout(this.refreshTokenTimer),
              (e = this.localStorage),
              D(void 0, void 0, void 0, function* () {
                k() &&
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
                  S(this, void 0, void 0, function* () {
                    this.networkRetries++;
                    const { error: e } = yield this._callRefreshToken();
                    e || (this.networkRetries = 0),
                      (null == e ? void 0 : e.message) === E &&
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
            !k() ||
            !(null === window || void 0 === window
              ? void 0
              : window.addEventListener)
          )
            return !1;
          try {
            null === window ||
              void 0 === window ||
              window.addEventListener("storage", (e) => {
                var n;
                if (e.key === f) {
                  const t = JSON.parse(String(e.newValue));
                  (
                    null === (n = null == t ? void 0 : t.currentSession) ||
                    void 0 === n
                      ? void 0
                      : n.access_token
                  )
                    ? (this._saveSession(t.currentSession),
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
            !k() ||
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
      var _ = function (e, n, t, r) {
        return new (t || (t = Promise))(function (i, o) {
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
            var n;
            e.done
              ? i(e.value)
              : ((n = e.value),
                n instanceof t
                  ? n
                  : new t(function (e) {
                      e(n);
                    })).then(s, a);
          }
          c((r = r.apply(e, n || [])).next());
        });
      };
      class P {
        constructor(e) {
          let n;
          Object.assign(this, e),
            (n = e.fetch
              ? e.fetch
              : "undefined" == typeof fetch
              ? (...e) =>
                  _(this, void 0, void 0, function* () {
                    return yield (yield s
                      .e(98)
                      .then(s.t.bind(s, 98, 23))).fetch(...e);
                  })
              : fetch),
            (this.fetch = (...e) => n(...e)),
            (this.shouldThrowOnError = e.shouldThrowOnError || !1),
            (this.allowEmpty = e.allowEmpty || !1);
        }
        throwOnError(e) {
          return null == e && (e = !0), (this.shouldThrowOnError = e), this;
        }
        then(e, n) {
          void 0 === this.schema ||
            (["GET", "HEAD"].includes(this.method)
              ? (this.headers["Accept-Profile"] = this.schema)
              : (this.headers["Content-Profile"] = this.schema)),
            "GET" !== this.method &&
              "HEAD" !== this.method &&
              (this.headers["Content-Type"] = "application/json");
          let t = this.fetch(this.url.toString(), {
            method: this.method,
            headers: this.headers,
            body: JSON.stringify(this.body),
            signal: this.signal,
          }).then((e) =>
            _(this, void 0, void 0, function* () {
              var n, t, r, i;
              let o = null,
                s = null,
                a = null,
                c = e.status,
                A = e.statusText;
              if (e.ok) {
                const i =
                  null === (n = this.headers.Prefer) || void 0 === n
                    ? void 0
                    : n.split(",").includes("return=minimal");
                if ("HEAD" !== this.method && !i) {
                  const n = yield e.text();
                  n &&
                    (s =
                      "text/csv" === this.headers.Accept ? n : JSON.parse(n));
                }
                const o =
                    null === (t = this.headers.Prefer) || void 0 === t
                      ? void 0
                      : t.match(/count=(exact|planned|estimated)/),
                  c =
                    null === (r = e.headers.get("content-range")) ||
                    void 0 === r
                      ? void 0
                      : r.split("/");
                o && c && c.length > 1 && (a = parseInt(c[1]));
              } else {
                const n = yield e.text();
                try {
                  o = JSON.parse(n);
                } catch (e) {
                  o = { message: n };
                }
                if (
                  (o &&
                    this.allowEmpty &&
                    (null === (i = null == o ? void 0 : o.details) ||
                    void 0 === i
                      ? void 0
                      : i.includes("Results contain 0 rows")) &&
                    ((o = null), (c = 200), (A = "OK")),
                  o && this.shouldThrowOnError)
                )
                  throw o;
              }
              return {
                error: o,
                data: s,
                count: a,
                status: c,
                statusText: A,
                body: s,
              };
            })
          );
          return (
            this.shouldThrowOnError ||
              (t = t.catch((e) => ({
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
            t.then(e, n)
          );
        }
      }
      class Y extends P {
        select(e = "*") {
          let n = !1;
          const t = e
            .split("")
            .map((e) => (/\s/.test(e) && !n ? "" : ('"' === e && (n = !n), e)))
            .join("");
          return this.url.searchParams.set("select", t), this;
        }
        order(
          e,
          { ascending: n = !0, nullsFirst: t = !1, foreignTable: r } = {}
        ) {
          const i = void 0 === r ? "order" : `${r}.order`,
            o = this.url.searchParams.get(i);
          return (
            this.url.searchParams.set(
              i,
              `${o ? `${o},` : ""}${e}.${n ? "asc" : "desc"}.${
                t ? "nullsfirst" : "nullslast"
              }`
            ),
            this
          );
        }
        limit(e, { foreignTable: n } = {}) {
          const t = void 0 === n ? "limit" : `${n}.limit`;
          return this.url.searchParams.set(t, `${e}`), this;
        }
        range(e, n, { foreignTable: t } = {}) {
          const r = void 0 === t ? "offset" : `${t}.offset`,
            i = void 0 === t ? "limit" : `${t}.limit`;
          return (
            this.url.searchParams.set(r, `${e}`),
            this.url.searchParams.set(i, "" + (n - e + 1)),
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
      class R extends Y {
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
        not(e, n, t) {
          return this.url.searchParams.append(`${e}`, `not.${n}.${t}`), this;
        }
        or(e, { foreignTable: n } = {}) {
          const t = void 0 === n ? "or" : `${n}.or`;
          return this.url.searchParams.append(t, `(${e})`), this;
        }
        eq(e, n) {
          return this.url.searchParams.append(`${e}`, `eq.${n}`), this;
        }
        neq(e, n) {
          return this.url.searchParams.append(`${e}`, `neq.${n}`), this;
        }
        gt(e, n) {
          return this.url.searchParams.append(`${e}`, `gt.${n}`), this;
        }
        gte(e, n) {
          return this.url.searchParams.append(`${e}`, `gte.${n}`), this;
        }
        lt(e, n) {
          return this.url.searchParams.append(`${e}`, `lt.${n}`), this;
        }
        lte(e, n) {
          return this.url.searchParams.append(`${e}`, `lte.${n}`), this;
        }
        like(e, n) {
          return this.url.searchParams.append(`${e}`, `like.${n}`), this;
        }
        ilike(e, n) {
          return this.url.searchParams.append(`${e}`, `ilike.${n}`), this;
        }
        is(e, n) {
          return this.url.searchParams.append(`${e}`, `is.${n}`), this;
        }
        in(e, n) {
          const t = n
            .map((e) =>
              "string" == typeof e && new RegExp("[,()]").test(e)
                ? `"${e}"`
                : `${e}`
            )
            .join(",");
          return this.url.searchParams.append(`${e}`, `in.(${t})`), this;
        }
        contains(e, n) {
          return (
            "string" == typeof n
              ? this.url.searchParams.append(`${e}`, `cs.${n}`)
              : Array.isArray(n)
              ? this.url.searchParams.append(`${e}`, `cs.{${n.join(",")}}`)
              : this.url.searchParams.append(`${e}`, `cs.${JSON.stringify(n)}`),
            this
          );
        }
        containedBy(e, n) {
          return (
            "string" == typeof n
              ? this.url.searchParams.append(`${e}`, `cd.${n}`)
              : Array.isArray(n)
              ? this.url.searchParams.append(`${e}`, `cd.{${n.join(",")}}`)
              : this.url.searchParams.append(`${e}`, `cd.${JSON.stringify(n)}`),
            this
          );
        }
        rangeLt(e, n) {
          return this.url.searchParams.append(`${e}`, `sl.${n}`), this;
        }
        rangeGt(e, n) {
          return this.url.searchParams.append(`${e}`, `sr.${n}`), this;
        }
        rangeGte(e, n) {
          return this.url.searchParams.append(`${e}`, `nxl.${n}`), this;
        }
        rangeLte(e, n) {
          return this.url.searchParams.append(`${e}`, `nxr.${n}`), this;
        }
        rangeAdjacent(e, n) {
          return this.url.searchParams.append(`${e}`, `adj.${n}`), this;
        }
        overlaps(e, n) {
          return (
            "string" == typeof n
              ? this.url.searchParams.append(`${e}`, `ov.${n}`)
              : this.url.searchParams.append(`${e}`, `ov.{${n.join(",")}}`),
            this
          );
        }
        textSearch(e, n, { config: t, type: r = null } = {}) {
          let i = "";
          "plain" === r
            ? (i = "pl")
            : "phrase" === r
            ? (i = "ph")
            : "websearch" === r && (i = "w");
          const o = void 0 === t ? "" : `(${t})`;
          return this.url.searchParams.append(`${e}`, `${i}fts${o}.${n}`), this;
        }
        fts(e, n, { config: t } = {}) {
          const r = void 0 === t ? "" : `(${t})`;
          return this.url.searchParams.append(`${e}`, `fts${r}.${n}`), this;
        }
        plfts(e, n, { config: t } = {}) {
          const r = void 0 === t ? "" : `(${t})`;
          return this.url.searchParams.append(`${e}`, `plfts${r}.${n}`), this;
        }
        phfts(e, n, { config: t } = {}) {
          const r = void 0 === t ? "" : `(${t})`;
          return this.url.searchParams.append(`${e}`, `phfts${r}.${n}`), this;
        }
        wfts(e, n, { config: t } = {}) {
          const r = void 0 === t ? "" : `(${t})`;
          return this.url.searchParams.append(`${e}`, `wfts${r}.${n}`), this;
        }
        filter(e, n, t) {
          return this.url.searchParams.append(`${e}`, `${n}.${t}`), this;
        }
        match(e) {
          return (
            Object.keys(e).forEach((n) => {
              this.url.searchParams.append(`${n}`, `eq.${e[n]}`);
            }),
            this
          );
        }
      }
      class G extends P {
        constructor(
          e,
          { headers: n = {}, schema: t, fetch: r, shouldThrowOnError: i } = {}
        ) {
          super({ fetch: r, shouldThrowOnError: i }),
            (this.url = new URL(e)),
            (this.headers = Object.assign({}, n)),
            (this.schema = t);
        }
        select(e = "*", { head: n = !1, count: t = null } = {}) {
          this.method = "GET";
          let r = !1;
          const i = e
            .split("")
            .map((e) => (/\s/.test(e) && !r ? "" : ('"' === e && (r = !r), e)))
            .join("");
          return (
            this.url.searchParams.set("select", i),
            t && (this.headers.Prefer = `count=${t}`),
            n && (this.method = "HEAD"),
            new R(this)
          );
        }
        insert(
          e,
          {
            upsert: n = !1,
            onConflict: t,
            returning: r = "representation",
            count: i = null,
          } = {}
        ) {
          this.method = "POST";
          const o = [`return=${r}`];
          if (
            (n && o.push("resolution=merge-duplicates"),
            n && void 0 !== t && this.url.searchParams.set("on_conflict", t),
            (this.body = e),
            i && o.push(`count=${i}`),
            this.headers.Prefer && o.unshift(this.headers.Prefer),
            (this.headers.Prefer = o.join(",")),
            Array.isArray(e))
          ) {
            const n = e.reduce((e, n) => e.concat(Object.keys(n)), []);
            if (n.length > 0) {
              const e = [...new Set(n)].map((e) => `"${e}"`);
              this.url.searchParams.set("columns", e.join(","));
            }
          }
          return new R(this);
        }
        upsert(
          e,
          {
            onConflict: n,
            returning: t = "representation",
            count: r = null,
            ignoreDuplicates: i = !1,
          } = {}
        ) {
          this.method = "POST";
          const o = [
            `resolution=${i ? "ignore" : "merge"}-duplicates`,
            `return=${t}`,
          ];
          return (
            void 0 !== n && this.url.searchParams.set("on_conflict", n),
            (this.body = e),
            r && o.push(`count=${r}`),
            this.headers.Prefer && o.unshift(this.headers.Prefer),
            (this.headers.Prefer = o.join(",")),
            new R(this)
          );
        }
        update(e, { returning: n = "representation", count: t = null } = {}) {
          this.method = "PATCH";
          const r = [`return=${n}`];
          return (
            (this.body = e),
            t && r.push(`count=${t}`),
            this.headers.Prefer && r.unshift(this.headers.Prefer),
            (this.headers.Prefer = r.join(",")),
            new R(this)
          );
        }
        delete({ returning: e = "representation", count: n = null } = {}) {
          this.method = "DELETE";
          const t = [`return=${e}`];
          return (
            n && t.push(`count=${n}`),
            this.headers.Prefer && t.unshift(this.headers.Prefer),
            (this.headers.Prefer = t.join(",")),
            new R(this)
          );
        }
      }
      class $ extends P {
        constructor(
          e,
          { headers: n = {}, schema: t, fetch: r, shouldThrowOnError: i } = {}
        ) {
          super({ fetch: r, shouldThrowOnError: i }),
            (this.url = new URL(e)),
            (this.headers = Object.assign({}, n)),
            (this.schema = t);
        }
        rpc(e, { head: n = !1, count: t = null } = {}) {
          return (
            n
              ? ((this.method = "HEAD"),
                e &&
                  Object.entries(e).forEach(([e, n]) => {
                    this.url.searchParams.append(e, n);
                  }))
              : ((this.method = "POST"), (this.body = e)),
            t &&
              (void 0 !== this.headers.Prefer
                ? (this.headers.Prefer += `,count=${t}`)
                : (this.headers.Prefer = `count=${t}`)),
            new R(this)
          );
        }
      }
      const Z = { "X-Client-Info": "postgrest-js/0.37.4" };
      class F {
        constructor(
          e,
          { headers: n = {}, schema: t, fetch: r, throwOnError: i } = {}
        ) {
          (this.url = e),
            (this.headers = Object.assign(Object.assign({}, Z), n)),
            (this.schema = t),
            (this.fetch = r),
            (this.shouldThrowOnError = i);
        }
        auth(e) {
          return (this.headers.Authorization = `Bearer ${e}`), this;
        }
        from(e) {
          const n = `${this.url}/${e}`;
          return new G(n, {
            headers: this.headers,
            schema: this.schema,
            fetch: this.fetch,
            shouldThrowOnError: this.shouldThrowOnError,
          });
        }
        rpc(e, n, { head: t = !1, count: r = null } = {}) {
          const i = `${this.url}/rpc/${e}`;
          return new $(i, {
            headers: this.headers,
            schema: this.schema,
            fetch: this.fetch,
            shouldThrowOnError: this.shouldThrowOnError,
          }).rpc(n, { head: t, count: r });
        }
      }
      var W;
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
      })(W || (W = {}));
      const H = (e, n, t = {}) => {
          var r;
          const i = null !== (r = t.skipTypes) && void 0 !== r ? r : [];
          return Object.keys(n).reduce(
            (t, r) => ((t[r] = J(r, e, n, i)), t),
            {}
          );
        },
        J = (e, n, t, r) => {
          const i = n.find((n) => n.name === e),
            o = null == i ? void 0 : i.type,
            s = t[e];
          return o && !r.includes(o) ? q(o, s) : X(s);
        },
        q = (e, n) => {
          if ("_" === e.charAt(0)) {
            const t = e.slice(1, e.length);
            return ne(n, t);
          }
          switch (e) {
            case W.bool:
              return V(n);
            case W.float4:
            case W.float8:
            case W.int2:
            case W.int4:
            case W.int8:
            case W.numeric:
            case W.oid:
              return K(n);
            case W.json:
            case W.jsonb:
              return ee(n);
            case W.timestamp:
              return te(n);
            case W.abstime:
            case W.date:
            case W.daterange:
            case W.int4range:
            case W.int8range:
            case W.money:
            case W.reltime:
            case W.text:
            case W.time:
            case W.timestamptz:
            case W.timetz:
            case W.tsrange:
            case W.tstzrange:
            default:
              return X(n);
          }
        },
        X = (e) => e,
        V = (e) => {
          switch (e) {
            case "t":
              return !0;
            case "f":
              return !1;
            default:
              return e;
          }
        },
        K = (e) => {
          if ("string" == typeof e) {
            const n = parseFloat(e);
            if (!Number.isNaN(n)) return n;
          }
          return e;
        },
        ee = (e) => {
          if ("string" == typeof e)
            try {
              return JSON.parse(e);
            } catch (n) {
              return console.log(`JSON parse error: ${n}`), e;
            }
          return e;
        },
        ne = (e, n) => {
          if ("string" != typeof e) return e;
          const t = e.length - 1,
            r = e[t];
          if ("{" === e[0] && "}" === r) {
            let r;
            const i = e.slice(1, t);
            try {
              r = JSON.parse("[" + i + "]");
            } catch (e) {
              r = i ? i.split(",") : [];
            }
            return r.map((e) => q(n, e));
          }
          return e;
        },
        te = (e) => ("string" == typeof e ? e.replace(" ", "T") : e);
      var re = s(840);
      const ie = { "X-Client-Info": "realtime-js/1.7.4" };
      var oe, se, ae, ce, Ae;
      !(function (e) {
        (e[(e.connecting = 0)] = "connecting"),
          (e[(e.open = 1)] = "open"),
          (e[(e.closing = 2)] = "closing"),
          (e[(e.closed = 3)] = "closed");
      })(oe || (oe = {})),
        (function (e) {
          (e.closed = "closed"),
            (e.errored = "errored"),
            (e.joined = "joined"),
            (e.joining = "joining"),
            (e.leaving = "leaving");
        })(se || (se = {})),
        (function (e) {
          (e.close = "phx_close"),
            (e.error = "phx_error"),
            (e.join = "phx_join"),
            (e.reply = "phx_reply"),
            (e.leave = "phx_leave"),
            (e.access_token = "access_token");
        })(ae || (ae = {})),
        (function (e) {
          e.websocket = "websocket";
        })(ce || (ce = {})),
        (function (e) {
          (e.Connecting = "connecting"),
            (e.Open = "open"),
            (e.Closing = "closing"),
            (e.Closed = "closed");
        })(Ae || (Ae = {}));
      class le {
        constructor(e, n) {
          (this.callback = e),
            (this.timerCalc = n),
            (this.timer = void 0),
            (this.tries = 0),
            (this.callback = e),
            (this.timerCalc = n);
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
      class de {
        constructor() {
          this.HEADER_LENGTH = 1;
        }
        decode(e, n) {
          return e.constructor === ArrayBuffer
            ? n(this._binaryDecode(e))
            : n("string" == typeof e ? JSON.parse(e) : {});
        }
        _binaryDecode(e) {
          const n = new DataView(e),
            t = new TextDecoder();
          return this._decodeBroadcast(e, n, t);
        }
        _decodeBroadcast(e, n, t) {
          const r = n.getUint8(1),
            i = n.getUint8(2);
          let o = this.HEADER_LENGTH + 2;
          const s = t.decode(e.slice(o, o + r));
          o += r;
          const a = t.decode(e.slice(o, o + i));
          return (
            (o += i),
            {
              ref: null,
              topic: s,
              event: a,
              payload: JSON.parse(t.decode(e.slice(o, e.byteLength))),
            }
          );
        }
      }
      class ue {
        constructor(e, n, t = {}, r = 1e4) {
          (this.channel = e),
            (this.event = n),
            (this.payload = t),
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
        receive(e, n) {
          var t;
          return (
            this._hasReceived(e) &&
              n(
                null === (t = this.receivedResp) || void 0 === t
                  ? void 0
                  : t.response
              ),
            this.recHooks.push({ status: e, callback: n }),
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
        trigger(e, n) {
          this.refEvent &&
            this.channel.trigger(this.refEvent, { status: e, response: n });
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
        _matchReceive({ status: e, response: n }) {
          this.recHooks
            .filter((n) => n.status === e)
            .forEach((e) => e.callback(n));
        }
        _hasReceived(e) {
          return this.receivedResp && this.receivedResp.status === e;
        }
      }
      class he {
        constructor(e, n = {}, t) {
          (this.topic = e),
            (this.params = n),
            (this.socket = t),
            (this.bindings = []),
            (this.state = se.closed),
            (this.joinedOnce = !1),
            (this.pushBuffer = []),
            (this.timeout = this.socket.timeout),
            (this.joinPush = new ue(this, ae.join, this.params, this.timeout)),
            (this.rejoinTimer = new le(
              () => this.rejoinUntilConnected(),
              this.socket.reconnectAfterMs
            )),
            this.joinPush.receive("ok", () => {
              (this.state = se.joined),
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
                (this.state = se.closed),
                this.socket.remove(this);
            }),
            this.onError((e) => {
              this.isLeaving() ||
                this.isClosed() ||
                (this.socket.log("channel", `error ${this.topic}`, e),
                (this.state = se.errored),
                this.rejoinTimer.scheduleTimeout());
            }),
            this.joinPush.receive("timeout", () => {
              this.isJoining() &&
                (this.socket.log(
                  "channel",
                  `timeout ${this.topic}`,
                  this.joinPush.timeout
                ),
                (this.state = se.errored),
                this.rejoinTimer.scheduleTimeout());
            }),
            this.on(ae.reply, (e, n) => {
              this.trigger(this.replyEventName(n), e);
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
          this.on(ae.close, e);
        }
        onError(e) {
          this.on(ae.error, (n) => e(n));
        }
        on(e, n) {
          this.bindings.push({ event: e, callback: n });
        }
        off(e) {
          this.bindings = this.bindings.filter((n) => n.event !== e);
        }
        canPush() {
          return this.socket.isConnected() && this.isJoined();
        }
        push(e, n, t = this.timeout) {
          if (!this.joinedOnce)
            throw `tried to push '${e}' to '${this.topic}' before joining. Use channel.subscribe() before pushing events`;
          let r = new ue(this, e, n, t);
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
          this.state = se.leaving;
          let n = () => {
            this.socket.log("channel", `leave ${this.topic}`),
              this.trigger(ae.close, "leave", this.joinRef());
          };
          this.joinPush.destroy();
          let t = new ue(this, ae.leave, {}, e);
          return (
            t.receive("ok", () => n()).receive("timeout", () => n()),
            t.send(),
            this.canPush() || t.trigger("ok", {}),
            t
          );
        }
        onMessage(e, n, t) {
          return n;
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
            (this.state = se.joining),
            this.joinPush.resend(e));
        }
        trigger(e, n, t) {
          let { close: r, error: i, leave: o, join: s } = ae;
          if (t && [r, i, o, s].indexOf(e) >= 0 && t !== this.joinRef()) return;
          let a = this.onMessage(e, n, t);
          if (n && !a)
            throw "channel onMessage callbacks must return the payload, modified or unmodified";
          this.bindings
            .filter((t) =>
              "*" === t.event
                ? e === (null == n ? void 0 : n.type)
                : t.event === e
            )
            .map((e) => e.callback(a, t));
        }
        replyEventName(e) {
          return `chan_reply_${e}`;
        }
        isClosed() {
          return this.state === se.closed;
        }
        isErrored() {
          return this.state === se.errored;
        }
        isJoined() {
          return this.state === se.joined;
        }
        isJoining() {
          return this.state === se.joining;
        }
        isLeaving() {
          return this.state === se.leaving;
        }
      }
      const ge = () => {};
      class pe {
        constructor(e, n) {
          (this.accessToken = null),
            (this.channels = []),
            (this.endPoint = ""),
            (this.headers = ie),
            (this.params = {}),
            (this.timeout = 1e4),
            (this.transport = re.w3cwebsocket),
            (this.heartbeatIntervalMs = 3e4),
            (this.longpollerTimeout = 2e4),
            (this.heartbeatTimer = void 0),
            (this.pendingHeartbeatRef = null),
            (this.ref = 0),
            (this.logger = ge),
            (this.conn = null),
            (this.sendBuffer = []),
            (this.serializer = new de()),
            (this.stateChangeCallbacks = {
              open: [],
              close: [],
              error: [],
              message: [],
            }),
            (this.endPoint = `${e}/${ce.websocket}`),
            (null == n ? void 0 : n.params) && (this.params = n.params),
            (null == n ? void 0 : n.headers) &&
              (this.headers = Object.assign(
                Object.assign({}, this.headers),
                n.headers
              )),
            (null == n ? void 0 : n.timeout) && (this.timeout = n.timeout),
            (null == n ? void 0 : n.logger) && (this.logger = n.logger),
            (null == n ? void 0 : n.transport) &&
              (this.transport = n.transport),
            (null == n ? void 0 : n.heartbeatIntervalMs) &&
              (this.heartbeatIntervalMs = n.heartbeatIntervalMs),
            (null == n ? void 0 : n.longpollerTimeout) &&
              (this.longpollerTimeout = n.longpollerTimeout),
            (this.reconnectAfterMs = (null == n ? void 0 : n.reconnectAfterMs)
              ? n.reconnectAfterMs
              : (e) => [1e3, 2e3, 5e3, 1e4][e - 1] || 1e4),
            (this.encode = (null == n ? void 0 : n.encode)
              ? n.encode
              : (e, n) => n(JSON.stringify(e))),
            (this.decode = (null == n ? void 0 : n.decode)
              ? n.decode
              : this.serializer.decode.bind(this.serializer)),
            (this.reconnectTimer = new le(() => {
              return (
                (e = this),
                (n = void 0),
                (r = function* () {
                  yield this.disconnect(), this.connect();
                }),
                new ((t = void 0) || (t = Promise))(function (i, o) {
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
                    var n;
                    e.done
                      ? i(e.value)
                      : ((n = e.value),
                        n instanceof t
                          ? n
                          : new t(function (e) {
                              e(n);
                            })).then(s, a);
                  }
                  c((r = r.apply(e, n || [])).next());
                })
              );
              var e, n, t, r;
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
        disconnect(e, n) {
          return new Promise((t, r) => {
            try {
              this.conn &&
                ((this.conn.onclose = function () {}),
                e ? this.conn.close(e, n || "") : this.conn.close(),
                (this.conn = null),
                this.heartbeatTimer && clearInterval(this.heartbeatTimer),
                this.reconnectTimer.reset()),
                t({ error: null, data: !0 });
            } catch (e) {
              t({ error: e, data: !1 });
            }
          });
        }
        log(e, n, t) {
          this.logger(e, n, t);
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
            case oe.connecting:
              return Ae.Connecting;
            case oe.open:
              return Ae.Open;
            case oe.closing:
              return Ae.Closing;
            default:
              return Ae.Closed;
          }
        }
        isConnected() {
          return this.connectionState() === Ae.Open;
        }
        remove(e) {
          this.channels = this.channels.filter(
            (n) => n.joinRef() !== e.joinRef()
          );
        }
        channel(e, n = {}) {
          const t = new he(e, n, this);
          return this.channels.push(t), t;
        }
        push(e) {
          const { topic: n, event: t, payload: r, ref: i } = e;
          let o = () => {
            this.encode(e, (e) => {
              var n;
              null === (n = this.conn) || void 0 === n || n.send(e);
            });
          };
          this.log("push", `${n} ${t} (${i})`, r),
            this.isConnected() ? o() : this.sendBuffer.push(o);
        }
        onConnMessage(e) {
          this.decode(e.data, (e) => {
            let { topic: n, event: t, payload: r, ref: i } = e;
            ((i && i === this.pendingHeartbeatRef) ||
              t === (null == r ? void 0 : r.type)) &&
              (this.pendingHeartbeatRef = null),
              this.log(
                "receive",
                `${r.status || ""} ${n} ${t} ${(i && "(" + i + ")") || ""}`,
                r
              ),
              this.channels
                .filter((e) => e.isMember(n))
                .forEach((e) => e.trigger(t, r, i)),
              this.stateChangeCallbacks.message.forEach((n) => n(e));
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
            this.channels.forEach((n) => {
              e && n.updateJoinPayload({ user_token: e }),
                n.joinedOnce &&
                  n.isJoined() &&
                  n.push(ae.access_token, { access_token: e });
            });
        }
        leaveOpenTopic(e) {
          let n = this.channels.find(
            (n) => n.topic === e && (n.isJoined() || n.isJoining())
          );
          n &&
            (this.log("transport", `leaving duplicate topic "${e}"`),
            n.unsubscribe());
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
            this.stateChangeCallbacks.close.forEach((n) => n(e));
        }
        _onConnError(e) {
          this.log("transport", e.message),
            this._triggerChanError(),
            this.stateChangeCallbacks.error.forEach((n) => n(e));
        }
        _triggerChanError() {
          this.channels.forEach((e) => e.trigger(ae.error));
        }
        _appendParams(e, n) {
          if (0 === Object.keys(n).length) return e;
          const t = e.match(/\?/) ? "&" : "?";
          return `${e}${t}${new URLSearchParams(n)}`;
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
      class me {
        constructor(e, n, t, r) {
          const i = {},
            o = "*" === r ? `realtime:${t}` : `realtime:${t}:${r}`,
            s = n.Authorization.split(" ")[1];
          s && (i.user_token = s), (this.subscription = e.channel(o, i));
        }
        getPayloadRecords(e) {
          const n = { new: {}, old: {} };
          return (
            ("INSERT" !== e.type && "UPDATE" !== e.type) ||
              (n.new = H(e.columns, e.record)),
            ("UPDATE" !== e.type && "DELETE" !== e.type) ||
              (n.old = H(e.columns, e.old_record)),
            n
          );
        }
        on(e, n) {
          return (
            this.subscription.on(e, (e) => {
              let t = {
                schema: e.schema,
                table: e.table,
                commit_timestamp: e.commit_timestamp,
                eventType: e.type,
                new: {},
                old: {},
                errors: e.errors,
              };
              (t = Object.assign(
                Object.assign({}, t),
                this.getPayloadRecords(e)
              )),
                n(t);
            }),
            this
          );
        }
        subscribe(e = () => {}) {
          return (
            this.subscription.onError((n) => e("SUBSCRIPTION_ERROR", n)),
            this.subscription.onClose(() => e("CLOSED")),
            this.subscription
              .subscribe()
              .receive("ok", () => e("SUBSCRIBED"))
              .receive("error", (n) => e("SUBSCRIPTION_ERROR", n))
              .receive("timeout", () => e("RETRYING_AFTER_TIMEOUT")),
            this.subscription
          );
        }
      }
      class we extends G {
        constructor(
          e,
          {
            headers: n = {},
            schema: t,
            realtime: r,
            table: i,
            fetch: o,
            shouldThrowOnError: s,
          }
        ) {
          super(e, { headers: n, schema: t, fetch: o, shouldThrowOnError: s }),
            (this._subscription = null),
            (this._realtime = r),
            (this._headers = n),
            (this._schema = t),
            (this._table = i);
        }
        on(e, n) {
          return (
            this._realtime.isConnected() || this._realtime.connect(),
            this._subscription ||
              (this._subscription = new me(
                this._realtime,
                this._headers,
                this._schema,
                this._table
              )),
            this._subscription.on(e, n)
          );
        }
      }
      const Ee = { "X-Client-Info": "storage-js/1.7.3" };
      var fe = function (e, n, t, r) {
        return new (t || (t = Promise))(function (i, o) {
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
            var n;
            e.done
              ? i(e.value)
              : ((n = e.value),
                n instanceof t
                  ? n
                  : new t(function (e) {
                      e(n);
                    })).then(s, a);
          }
          c((r = r.apply(e, n || [])).next());
        });
      };
      const Ce = (e) =>
        e.msg ||
        e.message ||
        e.error_description ||
        e.error ||
        JSON.stringify(e);
      function be(e, n, t, r, i, o) {
        return fe(this, void 0, void 0, function* () {
          return new Promise((s, a) => {
            e(
              t,
              ((e, n, t, r) => {
                const i = {
                  method: e,
                  headers: (null == n ? void 0 : n.headers) || {},
                };
                return "GET" === e
                  ? i
                  : ((i.headers = Object.assign(
                      { "Content-Type": "application/json" },
                      null == n ? void 0 : n.headers
                    )),
                    (i.body = JSON.stringify(r)),
                    Object.assign(Object.assign({}, i), t));
              })(n, r, i, o)
            )
              .then((e) => {
                if (!e.ok) throw e;
                return (null == r ? void 0 : r.noResolveJson) ? s(e) : e.json();
              })
              .then((e) => s(e))
              .catch((e) =>
                ((e, n) => {
                  if ("function" != typeof e.json) return n(e);
                  e.json().then((t) =>
                    n({
                      message: Ce(t),
                      status: (null == e ? void 0 : e.status) || 500,
                    })
                  );
                })(e, a)
              );
          });
        });
      }
      function ye(e, n, t, r) {
        return fe(this, void 0, void 0, function* () {
          return be(e, "GET", n, t, r);
        });
      }
      function Me(e, n, t, r, i) {
        return fe(this, void 0, void 0, function* () {
          return be(e, "POST", n, r, i, t);
        });
      }
      function Be(e, n, t, r, i) {
        return fe(this, void 0, void 0, function* () {
          return be(e, "DELETE", n, r, i, t);
        });
      }
      const xe = (e) => {
        let n;
        return (
          (n =
            e ||
            ("undefined" == typeof fetch
              ? (...e) => {
                  return (
                    (n = void 0),
                    (t = void 0),
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
                      function c(n) {
                        var t;
                        n.done
                          ? e(n.value)
                          : ((t = n.value),
                            t instanceof r
                              ? t
                              : new r(function (e) {
                                  e(t);
                                })).then(s, a);
                      }
                      c((i = i.apply(n, t || [])).next());
                    })
                  );
                  var n, t, r, i;
                }
              : fetch)),
          (...e) => n(...e)
        );
      };
      var Ne = function (e, n, t, r) {
          return new (t || (t = Promise))(function (i, o) {
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
              var n;
              e.done
                ? i(e.value)
                : ((n = e.value),
                  n instanceof t
                    ? n
                    : new t(function (e) {
                        e(n);
                      })).then(s, a);
            }
            c((r = r.apply(e, n || [])).next());
          });
        },
        ve = function (e, n, t, r) {
          return new (t || (t = Promise))(function (i, o) {
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
              var n;
              e.done
                ? i(e.value)
                : ((n = e.value),
                  n instanceof t
                    ? n
                    : new t(function (e) {
                        e(n);
                      })).then(s, a);
            }
            c((r = r.apply(e, n || [])).next());
          });
        };
      const Ie = {
          limit: 100,
          offset: 0,
          sortBy: { column: "name", order: "asc" },
        },
        De = {
          cacheControl: "3600",
          contentType: "text/plain;charset=UTF-8",
          upsert: !1,
        };
      class je {
        constructor(e, n = {}, t, r) {
          (this.url = e),
            (this.headers = n),
            (this.bucketId = t),
            (this.fetch = xe(r));
        }
        uploadOrUpdate(e, n, t, r) {
          return ve(this, void 0, void 0, function* () {
            try {
              let i;
              const o = Object.assign(Object.assign({}, De), r),
                s = Object.assign(
                  Object.assign({}, this.headers),
                  "POST" === e && { "x-upsert": String(o.upsert) }
                );
              "undefined" != typeof Blob && t instanceof Blob
                ? ((i = new FormData()),
                  i.append("cacheControl", o.cacheControl),
                  i.append("", t))
                : "undefined" != typeof FormData && t instanceof FormData
                ? ((i = t), i.append("cacheControl", o.cacheControl))
                : ((i = t),
                  (s["cache-control"] = `max-age=${o.cacheControl}`),
                  (s["content-type"] = o.contentType));
              const a = this._removeEmptyFolders(n),
                c = this._getFinalPath(a),
                A = yield this.fetch(`${this.url}/object/${c}`, {
                  method: e,
                  body: i,
                  headers: s,
                });
              return A.ok
                ? { data: { Key: c }, error: null }
                : { data: null, error: yield A.json() };
            } catch (e) {
              return { data: null, error: e };
            }
          });
        }
        upload(e, n, t) {
          return ve(this, void 0, void 0, function* () {
            return this.uploadOrUpdate("POST", e, n, t);
          });
        }
        update(e, n, t) {
          return ve(this, void 0, void 0, function* () {
            return this.uploadOrUpdate("PUT", e, n, t);
          });
        }
        move(e, n) {
          return ve(this, void 0, void 0, function* () {
            try {
              return {
                data: yield Me(
                  this.fetch,
                  `${this.url}/object/move`,
                  { bucketId: this.bucketId, sourceKey: e, destinationKey: n },
                  { headers: this.headers }
                ),
                error: null,
              };
            } catch (e) {
              return { data: null, error: e };
            }
          });
        }
        copy(e, n) {
          return ve(this, void 0, void 0, function* () {
            try {
              return {
                data: yield Me(
                  this.fetch,
                  `${this.url}/object/copy`,
                  { bucketId: this.bucketId, sourceKey: e, destinationKey: n },
                  { headers: this.headers }
                ),
                error: null,
              };
            } catch (e) {
              return { data: null, error: e };
            }
          });
        }
        createSignedUrl(e, n) {
          return ve(this, void 0, void 0, function* () {
            try {
              const t = this._getFinalPath(e);
              let r = yield Me(
                this.fetch,
                `${this.url}/object/sign/${t}`,
                { expiresIn: n },
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
        createSignedUrls(e, n) {
          return ve(this, void 0, void 0, function* () {
            try {
              return {
                data: (yield Me(
                  this.fetch,
                  `${this.url}/object/sign/${this.bucketId}`,
                  { expiresIn: n, paths: e },
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
          return ve(this, void 0, void 0, function* () {
            try {
              const n = this._getFinalPath(e),
                t = yield ye(this.fetch, `${this.url}/object/${n}`, {
                  headers: this.headers,
                  noResolveJson: !0,
                });
              return { data: yield t.blob(), error: null };
            } catch (e) {
              return { data: null, error: e };
            }
          });
        }
        getPublicUrl(e) {
          try {
            const n = this._getFinalPath(e),
              t = `${this.url}/object/public/${n}`;
            return { data: { publicURL: t }, error: null, publicURL: t };
          } catch (e) {
            return { data: null, error: e, publicURL: null };
          }
        }
        remove(e) {
          return ve(this, void 0, void 0, function* () {
            try {
              return {
                data: yield Be(
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
        list(e, n, t) {
          return ve(this, void 0, void 0, function* () {
            try {
              const r = Object.assign(Object.assign(Object.assign({}, Ie), n), {
                prefix: e || "",
              });
              return {
                data: yield Me(
                  this.fetch,
                  `${this.url}/object/list/${this.bucketId}`,
                  r,
                  { headers: this.headers },
                  t
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
      class ke extends class {
        constructor(e, n = {}, t) {
          (this.url = e),
            (this.headers = Object.assign(Object.assign({}, Ee), n)),
            (this.fetch = xe(t));
        }
        listBuckets() {
          return Ne(this, void 0, void 0, function* () {
            try {
              return {
                data: yield ye(this.fetch, `${this.url}/bucket`, {
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
          return Ne(this, void 0, void 0, function* () {
            try {
              return {
                data: yield ye(this.fetch, `${this.url}/bucket/${e}`, {
                  headers: this.headers,
                }),
                error: null,
              };
            } catch (e) {
              return { data: null, error: e };
            }
          });
        }
        createBucket(e, n = { public: !1 }) {
          return Ne(this, void 0, void 0, function* () {
            try {
              return {
                data: (yield Me(
                  this.fetch,
                  `${this.url}/bucket`,
                  { id: e, name: e, public: n.public },
                  { headers: this.headers }
                )).name,
                error: null,
              };
            } catch (e) {
              return { data: null, error: e };
            }
          });
        }
        updateBucket(e, n) {
          return Ne(this, void 0, void 0, function* () {
            try {
              const t = yield (function (e, n, t, r, i) {
                return fe(this, void 0, void 0, function* () {
                  return be(e, "PUT", n, r, undefined, t);
                });
              })(
                this.fetch,
                `${this.url}/bucket/${e}`,
                { id: e, name: e, public: n.public },
                { headers: this.headers }
              );
              return { data: t, error: null };
            } catch (e) {
              return { data: null, error: e };
            }
          });
        }
        emptyBucket(e) {
          return Ne(this, void 0, void 0, function* () {
            try {
              return {
                data: yield Me(
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
          return Ne(this, void 0, void 0, function* () {
            try {
              return {
                data: yield Be(
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
        constructor(e, n = {}, t) {
          super(e, n, t);
        }
        from(e) {
          return new je(this.url, this.headers, e, this.fetch);
        }
      }
      class Te {
        constructor(e, { headers: n = {}, customFetch: t } = {}) {
          (this.url = e),
            (this.headers = n),
            (this.fetch = ((e) => {
              let n;
              return (
                (n =
                  e ||
                  ("undefined" == typeof fetch
                    ? (...e) => {
                        return (
                          (n = void 0),
                          (t = void 0),
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
                            function c(n) {
                              var t;
                              n.done
                                ? e(n.value)
                                : ((t = n.value),
                                  t instanceof r
                                    ? t
                                    : new r(function (e) {
                                        e(t);
                                      })).then(s, a);
                            }
                            c((i = i.apply(n, t || [])).next());
                          })
                        );
                        var n, t, r, i;
                      }
                    : fetch)),
                (...e) => n(...e)
              );
            })(t));
        }
        setAuth(e) {
          this.headers.Authorization = `Bearer ${e}`;
        }
        invoke(e, n) {
          return (
            (t = this),
            (r = void 0),
            (o = function* () {
              try {
                const { headers: t, body: r } = null != n ? n : {},
                  i = yield this.fetch(`${this.url}/${e}`, {
                    method: "POST",
                    headers: Object.assign({}, this.headers, t),
                    body: r,
                  }),
                  o = i.headers.get("x-relay-error");
                if (o && "true" === o)
                  return { data: null, error: new Error(yield i.text()) };
                let s;
                const { responseType: a } = null != n ? n : {};
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
            new ((i = void 0) || (i = Promise))(function (e, n) {
              function s(e) {
                try {
                  c(o.next(e));
                } catch (e) {
                  n(e);
                }
              }
              function a(e) {
                try {
                  c(o.throw(e));
                } catch (e) {
                  n(e);
                }
              }
              function c(n) {
                var t;
                n.done
                  ? e(n.value)
                  : ((t = n.value),
                    t instanceof i
                      ? t
                      : new i(function (e) {
                          e(t);
                        })).then(s, a);
              }
              c((o = o.apply(t, r || [])).next());
            })
          );
          var t, r, i, o;
        }
      }
      var ze = function (e, n, t, r) {
        return new (t || (t = Promise))(function (i, o) {
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
            var n;
            e.done
              ? i(e.value)
              : ((n = e.value),
                n instanceof t
                  ? n
                  : new t(function (e) {
                      e(n);
                    })).then(s, a);
          }
          c((r = r.apply(e, n || [])).next());
        });
      };
      const Oe = {
        schema: "public",
        autoRefreshToken: !0,
        persistSession: !0,
        detectSessionInUrl: !0,
        multiTab: !0,
        headers: w,
      };
      class Le {
        constructor(e, n, t) {
          if (((this.supabaseUrl = e), (this.supabaseKey = n), !e))
            throw new Error("supabaseUrl is required.");
          if (!n) throw new Error("supabaseKey is required.");
          const r = e.replace(/\/$/, ""),
            i = Object.assign(Object.assign({}, Oe), t);
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
              Object.assign({}, w),
              null == t ? void 0 : t.headers
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
          return new Te(this.functionsUrl, {
            headers: this._getAuthHeaders(),
            customFetch: this.fetch,
          });
        }
        get storage() {
          return new ke(this.storageUrl, this._getAuthHeaders(), this.fetch);
        }
        from(e) {
          const n = `${this.restUrl}/${e}`;
          return new we(n, {
            headers: this._getAuthHeaders(),
            schema: this.schema,
            realtime: this.realtime,
            table: e,
            fetch: this.fetch,
            shouldThrowOnError: this.shouldThrowOnError,
          });
        }
        rpc(e, n, { head: t = !1, count: r = null } = {}) {
          return this._initPostgRESTClient().rpc(e, n, { head: t, count: r });
        }
        removeAllSubscriptions() {
          return ze(this, void 0, void 0, function* () {
            const e = this.getSubscriptions().slice(),
              n = e.map((e) => this.removeSubscription(e));
            return (yield Promise.all(n)).map(({ error: n }, t) => ({
              data: { subscription: e[t] },
              error: n,
            }));
          });
        }
        removeSubscription(e) {
          return ze(this, void 0, void 0, function* () {
            const { error: n } = yield this._closeSubscription(e),
              t = this.getSubscriptions(),
              r = t.filter((e) => e.isJoined()).length;
            return (
              0 === t.length && (yield this.realtime.disconnect()),
              { data: { openSubscriptions: r }, error: n }
            );
          });
        }
        _closeSubscription(e) {
          return ze(this, void 0, void 0, function* () {
            let n = null;
            if (!e.isClosed()) {
              const { error: t } = yield this._unsubscribeSubscription(e);
              n = t;
            }
            return this.realtime.remove(e), { error: n };
          });
        }
        _unsubscribeSubscription(e) {
          return new Promise((n) => {
            e.unsubscribe()
              .receive("ok", () => n({ error: null }))
              .receive("error", (e) => n({ error: e }))
              .receive("timeout", () => n({ error: new Error("timed out") }));
          });
        }
        getSubscriptions() {
          return this.realtime.channels;
        }
        _initSupabaseAuthClient({
          autoRefreshToken: e,
          persistSession: n,
          detectSessionInUrl: t,
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
          return new Q({
            url: this.authUrl,
            headers: Object.assign(Object.assign({}, i), c),
            autoRefreshToken: e,
            persistSession: n,
            detectSessionInUrl: t,
            localStorage: r,
            fetch: o,
            cookieOptions: s,
            multiTab: a,
          });
        }
        _initRealtimeClient(e) {
          return new pe(
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
          return new F(this.restUrl, {
            headers: this._getAuthHeaders(),
            schema: this.schema,
            fetch: this.fetch,
            throwOnError: this.shouldThrowOnError,
          });
        }
        _getAuthHeaders() {
          var e, n;
          const t = Object.assign({}, this.headers),
            r =
              null !==
                (n =
                  null === (e = this.auth.session()) || void 0 === e
                    ? void 0
                    : e.access_token) && void 0 !== n
                ? n
                : this.supabaseKey;
          return (
            (t.apikey = this.supabaseKey),
            (t.Authorization = t.Authorization || `Bearer ${r}`),
            t
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
                  var n, t, r;
                  if ("supabase.auth.token" === e.key) {
                    const i = JSON.parse(String(e.newValue)),
                      o =
                        null !==
                          (t =
                            null ===
                              (n = null == i ? void 0 : i.currentSession) ||
                            void 0 === n
                              ? void 0
                              : n.access_token) && void 0 !== t
                          ? t
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
          let { data: e } = this.auth.onAuthStateChange((e, n) => {
            this._handleTokenChanged(
              e,
              null == n ? void 0 : n.access_token,
              "CLIENT"
            );
          });
          return e;
        }
        _handleTokenChanged(e, n, t) {
          ("TOKEN_REFRESHED" !== e && "SIGNED_IN" !== e) ||
          this.changedAccessToken === n
            ? ("SIGNED_OUT" !== e && "USER_DELETED" !== e) ||
              (this.realtime.setAuth(this.supabaseKey),
              "STORAGE" == t && this.auth.signOut())
            : (this.realtime.setAuth(n),
              "STORAGE" == t && this.auth.setAuth(n),
              (this.changedAccessToken = n));
        }
      }
      const Se = new Le(
        "https://rsfcqodmucagrxohmkgx.supabase.co",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InJzZmNxb2RtdWNhZ3J4b2hta2d4Iiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTY2MDkyNjk0OSwiZXhwIjoxOTc2NTAyOTQ5fQ.8PZmvfHrTPVNheNjYHyJJS2jZC5EjCIlOkQK3t2Tvwc",
        void 0
      );
      if ((console.log(Se.auth.user()), Se.auth.user())) {
        for (var Ue in (console.log(Se.auth.user().email),
        console.log(
          "admin@thetvs.com,vplvl1@thetvs.com,vplvl2@thetvs.com,vplvl3@thetvs.com".split(
            ","
          )
        ),
        "admin@thetvs.com,vplvl1@thetvs.com,vplvl2@thetvs.com,vplvl3@thetvs.com".split(
          ","
        ))) {
          if (
            Se.auth.user().email ==
            "admin@thetvs.com,vplvl1@thetvs.com,vplvl2@thetvs.com,vplvl3@thetvs.com".split(
              ","
            )[Ue]
          ) {
            document.getElementById("admin").classList.remove("hidden"),
              console.log(Ue);
            break;
          }
          document.getElementById("admin").classList.add("hidden");
        }
        document.getElementById("formie").classList.remove("hidden"),
          document.getElementById("notlogged").classList.add("hidden");
      } else
        document.getElementById("formie").classList.add("hidden"),
          document.getElementById("notlogged").classList.remove("hidden");
      !(async function () {
        let { data: e, error: n } = await Se.rpc("exportcolumn", {
          tablename: "Assembly",
        });
        console.log(n);
      })(),
        console.log("hiyo"),
        (window.openNav = function () {
          document.getElementById("mySidenav").style.width = "250px";
        }),
        (window.closeNav = function () {
          document.getElementById("mySidenav").style.width = "0";
        }),
        (window.logout = async function () {
          await Se.auth.signOut(), window.location.replace("index.html");
        }),
        (window.accessAdmin = function () {
          document.getElementById("admin").classList.contains("hidden")
            ? m().alert(
                "You have not been granted admin access",
                null,
                m().Icons.Failed
              )
            : (window.location.href = "admin.html");
        });
    })();
})();
