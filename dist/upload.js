(() => {
  var n,
    e,
    t,
    r,
    o = {
      265: (n, e, t) => {
        "use strict";
        t.d(e, { Z: () => b });
        var r = t(537),
          o = t.n(r),
          i = t(645),
          s = t.n(i),
          a = t(667),
          A = t.n(a),
          c = new URL(t(909), t.b),
          d = new URL(t(133), t.b),
          l = new URL(t(601), t.b),
          h = new URL(t(686), t.b),
          u = s()(o()),
          p = A()(c),
          g = A()(d),
          m = A()(l),
          f = A()(h);
        u.push([
          n.id,
          "/*\n! tailwindcss v3.1.8 | MIT License | https://tailwindcss.com\n*/\n\n/*\n1. Prevent padding and border from affecting element width. (https://github.com/mozdevs/cssremedy/issues/4)\n2. Allow adding a border to an element by just adding a border-width. (https://github.com/tailwindcss/tailwindcss/pull/116)\n*/\n\n*,\n::before,\n::after {\n  box-sizing: border-box;\n  /* 1 */\n  border-width: 0;\n  /* 2 */\n  border-style: solid;\n  /* 2 */\n  border-color: #e5e7eb;\n  /* 2 */\n}\n\n::before,\n::after {\n  --tw-content: '';\n}\n\n/*\n1. Use a consistent sensible line-height in all browsers.\n2. Prevent adjustments of font size after orientation changes in iOS.\n3. Use a more readable tab size.\n4. Use the user's configured `sans` font-family by default.\n*/\n\nhtml {\n  line-height: 1.5;\n  /* 1 */\n  -webkit-text-size-adjust: 100%;\n  /* 2 */\n  -moz-tab-size: 4;\n  /* 3 */\n  -o-tab-size: 4;\n     tab-size: 4;\n  /* 3 */\n  font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, Noto Sans, sans-serif, BlinkMacSystemFont, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, \"Noto Sans\", sans-serif, \"Apple Color Emoji\", \"Segoe UI Emoji\", \"Segoe UI Symbol\", \"Noto Color Emoji\";\n  /* 4 */\n}\n\n/*\n1. Remove the margin in all browsers.\n2. Inherit line-height from `html` so users can set them as a class directly on the `html` element.\n*/\n\nbody {\n  margin: 0;\n  /* 1 */\n  line-height: inherit;\n  /* 2 */\n}\n\n/*\n1. Add the correct height in Firefox.\n2. Correct the inheritance of border color in Firefox. (https://bugzilla.mozilla.org/show_bug.cgi?id=190655)\n3. Ensure horizontal rules are visible by default.\n*/\n\nhr {\n  height: 0;\n  /* 1 */\n  color: inherit;\n  /* 2 */\n  border-top-width: 1px;\n  /* 3 */\n}\n\n/*\nAdd the correct text decoration in Chrome, Edge, and Safari.\n*/\n\nabbr:where([title]) {\n  -webkit-text-decoration: underline dotted;\n          text-decoration: underline;\n          -webkit-text-decoration: underline dotted currentColor;\n                  text-decoration: underline dotted currentColor;\n}\n\n/*\nRemove the default font size and weight for headings.\n*/\n\nh1,\nh2,\nh3,\nh4,\nh5,\nh6 {\n  font-size: inherit;\n  font-weight: inherit;\n}\n\n/*\nReset links to optimize for opt-in styling instead of opt-out.\n*/\n\na {\n  color: inherit;\n  text-decoration: inherit;\n}\n\n/*\nAdd the correct font weight in Edge and Safari.\n*/\n\nb,\nstrong {\n  font-weight: bolder;\n}\n\n/*\n1. Use the user's configured `mono` font family by default.\n2. Correct the odd `em` font sizing in all browsers.\n*/\n\ncode,\nkbd,\nsamp,\npre {\n  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, \"Liberation Mono\", \"Courier New\", monospace;\n  /* 1 */\n  font-size: 1em;\n  /* 2 */\n}\n\n/*\nAdd the correct font size in all browsers.\n*/\n\nsmall {\n  font-size: 80%;\n}\n\n/*\nPrevent `sub` and `sup` elements from affecting the line height in all browsers.\n*/\n\nsub,\nsup {\n  font-size: 75%;\n  line-height: 0;\n  position: relative;\n  vertical-align: baseline;\n}\n\nsub {\n  bottom: -0.25em;\n}\n\nsup {\n  top: -0.5em;\n}\n\n/*\n1. Remove text indentation from table contents in Chrome and Safari. (https://bugs.chromium.org/p/chromium/issues/detail?id=999088, https://bugs.webkit.org/show_bug.cgi?id=201297)\n2. Correct table border color inheritance in all Chrome and Safari. (https://bugs.chromium.org/p/chromium/issues/detail?id=935729, https://bugs.webkit.org/show_bug.cgi?id=195016)\n3. Remove gaps between table borders by default.\n*/\n\ntable {\n  text-indent: 0;\n  /* 1 */\n  border-color: inherit;\n  /* 2 */\n  border-collapse: collapse;\n  /* 3 */\n}\n\n/*\n1. Change the font styles in all browsers.\n2. Remove the margin in Firefox and Safari.\n3. Remove default padding in all browsers.\n*/\n\nbutton,\ninput,\noptgroup,\nselect,\ntextarea {\n  font-family: inherit;\n  /* 1 */\n  font-size: 100%;\n  /* 1 */\n  font-weight: inherit;\n  /* 1 */\n  line-height: inherit;\n  /* 1 */\n  color: inherit;\n  /* 1 */\n  margin: 0;\n  /* 2 */\n  padding: 0;\n  /* 3 */\n}\n\n/*\nRemove the inheritance of text transform in Edge and Firefox.\n*/\n\nbutton,\nselect {\n  text-transform: none;\n}\n\n/*\n1. Correct the inability to style clickable types in iOS and Safari.\n2. Remove default button styles.\n*/\n\nbutton,\n[type='button'],\n[type='reset'],\n[type='submit'] {\n  -webkit-appearance: button;\n  /* 1 */\n  background-color: transparent;\n  /* 2 */\n  background-image: none;\n  /* 2 */\n}\n\n/*\nUse the modern Firefox focus style for all focusable elements.\n*/\n\n:-moz-focusring {\n  outline: auto;\n}\n\n/*\nRemove the additional `:invalid` styles in Firefox. (https://github.com/mozilla/gecko-dev/blob/2f9eacd9d3d995c937b4251a5557d95d494c9be1/layout/style/res/forms.css#L728-L737)\n*/\n\n:-moz-ui-invalid {\n  box-shadow: none;\n}\n\n/*\nAdd the correct vertical alignment in Chrome and Firefox.\n*/\n\nprogress {\n  vertical-align: baseline;\n}\n\n/*\nCorrect the cursor style of increment and decrement buttons in Safari.\n*/\n\n::-webkit-inner-spin-button,\n::-webkit-outer-spin-button {\n  height: auto;\n}\n\n/*\n1. Correct the odd appearance in Chrome and Safari.\n2. Correct the outline style in Safari.\n*/\n\n[type='search'] {\n  -webkit-appearance: textfield;\n  /* 1 */\n  outline-offset: -2px;\n  /* 2 */\n}\n\n/*\nRemove the inner padding in Chrome and Safari on macOS.\n*/\n\n::-webkit-search-decoration {\n  -webkit-appearance: none;\n}\n\n/*\n1. Correct the inability to style clickable types in iOS and Safari.\n2. Change font properties to `inherit` in Safari.\n*/\n\n::-webkit-file-upload-button {\n  -webkit-appearance: button;\n  /* 1 */\n  font: inherit;\n  /* 2 */\n}\n\n/*\nAdd the correct display in Chrome and Safari.\n*/\n\nsummary {\n  display: list-item;\n}\n\n/*\nRemoves the default spacing and border for appropriate elements.\n*/\n\nblockquote,\ndl,\ndd,\nh1,\nh2,\nh3,\nh4,\nh5,\nh6,\nhr,\nfigure,\np,\npre {\n  margin: 0;\n}\n\nfieldset {\n  margin: 0;\n  padding: 0;\n}\n\nlegend {\n  padding: 0;\n}\n\nol,\nul,\nmenu {\n  list-style: none;\n  margin: 0;\n  padding: 0;\n}\n\n/*\nPrevent resizing textareas horizontally by default.\n*/\n\ntextarea {\n  resize: vertical;\n}\n\n/*\n1. Reset the default placeholder opacity in Firefox. (https://github.com/tailwindlabs/tailwindcss/issues/3300)\n2. Set the default placeholder color to the user's configured gray 400 color.\n*/\n\ninput::-moz-placeholder, textarea::-moz-placeholder {\n  opacity: 1;\n  /* 1 */\n  color: #9ca3af;\n  /* 2 */\n}\n\ninput::placeholder,\ntextarea::placeholder {\n  opacity: 1;\n  /* 1 */\n  color: #9ca3af;\n  /* 2 */\n}\n\n/*\nSet the default cursor for buttons.\n*/\n\nbutton,\n[role=\"button\"] {\n  cursor: pointer;\n}\n\n/*\nMake sure disabled buttons don't get the pointer cursor.\n*/\n\n:disabled {\n  cursor: default;\n}\n\n/*\n1. Make replaced elements `display: block` by default. (https://github.com/mozdevs/cssremedy/issues/14)\n2. Add `vertical-align: middle` to align replaced elements more sensibly by default. (https://github.com/jensimmons/cssremedy/issues/14#issuecomment-634934210)\n   This can trigger a poorly considered lint error in some tools but is included by design.\n*/\n\nimg,\nsvg,\nvideo,\ncanvas,\naudio,\niframe,\nembed,\nobject {\n  display: block;\n  /* 1 */\n  vertical-align: middle;\n  /* 2 */\n}\n\n/*\nConstrain images and videos to the parent width and preserve their intrinsic aspect ratio. (https://github.com/mozdevs/cssremedy/issues/14)\n*/\n\nimg,\nvideo {\n  max-width: 100%;\n  height: auto;\n}\n\n[type='text'],[type='email'],[type='url'],[type='password'],[type='number'],[type='date'],[type='datetime-local'],[type='month'],[type='search'],[type='tel'],[type='time'],[type='week'],[multiple],textarea,select {\n  -webkit-appearance: none;\n     -moz-appearance: none;\n          appearance: none;\n  background-color: #fff;\n  border-color: #6b7280;\n  border-width: 1px;\n  border-radius: 0px;\n  padding-top: 0.5rem;\n  padding-right: 0.75rem;\n  padding-bottom: 0.5rem;\n  padding-left: 0.75rem;\n  font-size: 1rem;\n  line-height: 1.5rem;\n  --tw-shadow: 0 0 rgba(0,0,0,0);\n}\n\n[type='text']:focus, [type='email']:focus, [type='url']:focus, [type='password']:focus, [type='number']:focus, [type='date']:focus, [type='datetime-local']:focus, [type='month']:focus, [type='search']:focus, [type='tel']:focus, [type='time']:focus, [type='week']:focus, [multiple]:focus, textarea:focus, select:focus {\n  outline: 2px solid transparent;\n  outline-offset: 2px;\n  --tw-ring-inset: var(--tw-empty,/*!*/ /*!*/);\n  --tw-ring-offset-width: 0px;\n  --tw-ring-offset-color: #fff;\n  --tw-ring-color: #2563eb;\n  --tw-ring-offset-shadow: var(--tw-ring-inset) 0 0 0 var(--tw-ring-offset-width) var(--tw-ring-offset-color);\n  --tw-ring-shadow: var(--tw-ring-inset) 0 0 0 calc(1px + var(--tw-ring-offset-width)) var(--tw-ring-color);\n  box-shadow: var(--tw-ring-offset-shadow), var(--tw-ring-shadow), var(--tw-shadow);\n  border-color: #2563eb;\n}\n\ninput::-moz-placeholder, textarea::-moz-placeholder {\n  color: #6b7280;\n  opacity: 1;\n}\n\ninput::placeholder,textarea::placeholder {\n  color: #6b7280;\n  opacity: 1;\n}\n\n::-webkit-datetime-edit-fields-wrapper {\n  padding: 0;\n}\n\n::-webkit-date-and-time-value {\n  min-height: 1.5em;\n}\n\n::-webkit-datetime-edit,::-webkit-datetime-edit-year-field,::-webkit-datetime-edit-month-field,::-webkit-datetime-edit-day-field,::-webkit-datetime-edit-hour-field,::-webkit-datetime-edit-minute-field,::-webkit-datetime-edit-second-field,::-webkit-datetime-edit-millisecond-field,::-webkit-datetime-edit-meridiem-field {\n  padding-top: 0;\n  padding-bottom: 0;\n}\n\nselect {\n  background-image: url(" +
            p +
            ");\n  background-position: right 0.5rem center;\n  background-repeat: no-repeat;\n  background-size: 1.5em 1.5em;\n  padding-right: 2.5rem;\n  -webkit-print-color-adjust: exact;\n     color-adjust: exact;\n          print-color-adjust: exact;\n}\n\n[multiple] {\n  background-image: none;\n  background-image: initial;\n  background-position: 0 0;\n  background-position: initial;\n  background-repeat: repeat;\n  background-repeat: initial;\n  background-size: auto auto;\n  background-size: initial;\n  padding-right: 0.75rem;\n  -webkit-print-color-adjust: unset;\n     color-adjust: initial;\n          print-color-adjust: inherit;\n}\n\n[type='checkbox'],[type='radio'] {\n  -webkit-appearance: none;\n     -moz-appearance: none;\n          appearance: none;\n  padding: 0;\n  -webkit-print-color-adjust: exact;\n     color-adjust: exact;\n          print-color-adjust: exact;\n  display: inline-block;\n  vertical-align: middle;\n  background-origin: border-box;\n  -webkit-user-select: none;\n     -moz-user-select: none;\n          user-select: none;\n  flex-shrink: 0;\n  height: 1rem;\n  width: 1rem;\n  color: #2563eb;\n  background-color: #fff;\n  border-color: #6b7280;\n  border-width: 1px;\n  --tw-shadow: 0 0 rgba(0,0,0,0);\n}\n\n[type='checkbox'] {\n  border-radius: 0px;\n}\n\n[type='radio'] {\n  border-radius: 100%;\n}\n\n[type='checkbox']:focus,[type='radio']:focus {\n  outline: 2px solid transparent;\n  outline-offset: 2px;\n  --tw-ring-inset: var(--tw-empty,/*!*/ /*!*/);\n  --tw-ring-offset-width: 2px;\n  --tw-ring-offset-color: #fff;\n  --tw-ring-color: #2563eb;\n  --tw-ring-offset-shadow: var(--tw-ring-inset) 0 0 0 var(--tw-ring-offset-width) var(--tw-ring-offset-color);\n  --tw-ring-shadow: var(--tw-ring-inset) 0 0 0 calc(2px + var(--tw-ring-offset-width)) var(--tw-ring-color);\n  box-shadow: var(--tw-ring-offset-shadow), var(--tw-ring-shadow), var(--tw-shadow);\n}\n\n[type='checkbox']:checked,[type='radio']:checked {\n  border-color: transparent;\n  background-color: currentColor;\n  background-size: 100% 100%;\n  background-position: center;\n  background-repeat: no-repeat;\n}\n\n[type='checkbox']:checked {\n  background-image: url(" +
            g +
            ");\n}\n\n[type='radio']:checked {\n  background-image: url(" +
            m +
            ");\n}\n\n[type='checkbox']:checked:hover,[type='checkbox']:checked:focus,[type='radio']:checked:hover,[type='radio']:checked:focus {\n  border-color: transparent;\n  background-color: currentColor;\n}\n\n[type='checkbox']:indeterminate {\n  background-image: url(" +
            f +
            ");\n  border-color: transparent;\n  background-color: currentColor;\n  background-size: 100% 100%;\n  background-position: center;\n  background-repeat: no-repeat;\n}\n\n[type='checkbox']:indeterminate:hover,[type='checkbox']:indeterminate:focus {\n  border-color: transparent;\n  background-color: currentColor;\n}\n\n[type='file'] {\n  background: transparent none repeat 0 0 / auto auto padding-box border-box scroll;\n  background: initial;\n  border-color: inherit;\n  border-width: 0;\n  border-radius: 0;\n  padding: 0;\n  font-size: inherit;\n  line-height: inherit;\n}\n\n[type='file']:focus {\n  outline: 1px solid ButtonText;\n  outline: 1px auto -webkit-focus-ring-color;\n}\n\n*, ::before, ::after {\n  --tw-border-spacing-x: 0;\n  --tw-border-spacing-y: 0;\n  --tw-translate-x: 0;\n  --tw-translate-y: 0;\n  --tw-rotate: 0;\n  --tw-skew-x: 0;\n  --tw-skew-y: 0;\n  --tw-scale-x: 1;\n  --tw-scale-y: 1;\n  --tw-pan-x:  ;\n  --tw-pan-y:  ;\n  --tw-pinch-zoom:  ;\n  --tw-scroll-snap-strictness: proximity;\n  --tw-ordinal:  ;\n  --tw-slashed-zero:  ;\n  --tw-numeric-figure:  ;\n  --tw-numeric-spacing:  ;\n  --tw-numeric-fraction:  ;\n  --tw-ring-inset:  ;\n  --tw-ring-offset-width: 0px;\n  --tw-ring-offset-color: #fff;\n  --tw-ring-color: rgba(59, 130, 246, 0.5);\n  --tw-ring-offset-shadow: 0 0 rgba(0,0,0,0);\n  --tw-ring-shadow: 0 0 rgba(0,0,0,0);\n  --tw-shadow: 0 0 rgba(0,0,0,0);\n  --tw-shadow-colored: 0 0 rgba(0,0,0,0);\n  --tw-blur:  ;\n  --tw-brightness:  ;\n  --tw-contrast:  ;\n  --tw-grayscale:  ;\n  --tw-hue-rotate:  ;\n  --tw-invert:  ;\n  --tw-saturate:  ;\n  --tw-sepia:  ;\n  --tw-drop-shadow:  ;\n  --tw-backdrop-blur:  ;\n  --tw-backdrop-brightness:  ;\n  --tw-backdrop-contrast:  ;\n  --tw-backdrop-grayscale:  ;\n  --tw-backdrop-hue-rotate:  ;\n  --tw-backdrop-invert:  ;\n  --tw-backdrop-opacity:  ;\n  --tw-backdrop-saturate:  ;\n  --tw-backdrop-sepia:  ;\n}\n\n::-webkit-backdrop {\n  --tw-border-spacing-x: 0;\n  --tw-border-spacing-y: 0;\n  --tw-translate-x: 0;\n  --tw-translate-y: 0;\n  --tw-rotate: 0;\n  --tw-skew-x: 0;\n  --tw-skew-y: 0;\n  --tw-scale-x: 1;\n  --tw-scale-y: 1;\n  --tw-pan-x:  ;\n  --tw-pan-y:  ;\n  --tw-pinch-zoom:  ;\n  --tw-scroll-snap-strictness: proximity;\n  --tw-ordinal:  ;\n  --tw-slashed-zero:  ;\n  --tw-numeric-figure:  ;\n  --tw-numeric-spacing:  ;\n  --tw-numeric-fraction:  ;\n  --tw-ring-inset:  ;\n  --tw-ring-offset-width: 0px;\n  --tw-ring-offset-color: #fff;\n  --tw-ring-color: rgba(59, 130, 246, 0.5);\n  --tw-ring-offset-shadow: 0 0 rgba(0,0,0,0);\n  --tw-ring-shadow: 0 0 rgba(0,0,0,0);\n  --tw-shadow: 0 0 rgba(0,0,0,0);\n  --tw-shadow-colored: 0 0 rgba(0,0,0,0);\n  --tw-blur:  ;\n  --tw-brightness:  ;\n  --tw-contrast:  ;\n  --tw-grayscale:  ;\n  --tw-hue-rotate:  ;\n  --tw-invert:  ;\n  --tw-saturate:  ;\n  --tw-sepia:  ;\n  --tw-drop-shadow:  ;\n  --tw-backdrop-blur:  ;\n  --tw-backdrop-brightness:  ;\n  --tw-backdrop-contrast:  ;\n  --tw-backdrop-grayscale:  ;\n  --tw-backdrop-hue-rotate:  ;\n  --tw-backdrop-invert:  ;\n  --tw-backdrop-opacity:  ;\n  --tw-backdrop-saturate:  ;\n  --tw-backdrop-sepia:  ;\n}\n\n::backdrop {\n  --tw-border-spacing-x: 0;\n  --tw-border-spacing-y: 0;\n  --tw-translate-x: 0;\n  --tw-translate-y: 0;\n  --tw-rotate: 0;\n  --tw-skew-x: 0;\n  --tw-skew-y: 0;\n  --tw-scale-x: 1;\n  --tw-scale-y: 1;\n  --tw-pan-x:  ;\n  --tw-pan-y:  ;\n  --tw-pinch-zoom:  ;\n  --tw-scroll-snap-strictness: proximity;\n  --tw-ordinal:  ;\n  --tw-slashed-zero:  ;\n  --tw-numeric-figure:  ;\n  --tw-numeric-spacing:  ;\n  --tw-numeric-fraction:  ;\n  --tw-ring-inset:  ;\n  --tw-ring-offset-width: 0px;\n  --tw-ring-offset-color: #fff;\n  --tw-ring-color: rgba(59, 130, 246, 0.5);\n  --tw-ring-offset-shadow: 0 0 rgba(0,0,0,0);\n  --tw-ring-shadow: 0 0 rgba(0,0,0,0);\n  --tw-shadow: 0 0 rgba(0,0,0,0);\n  --tw-shadow-colored: 0 0 rgba(0,0,0,0);\n  --tw-blur:  ;\n  --tw-brightness:  ;\n  --tw-contrast:  ;\n  --tw-grayscale:  ;\n  --tw-hue-rotate:  ;\n  --tw-invert:  ;\n  --tw-saturate:  ;\n  --tw-sepia:  ;\n  --tw-drop-shadow:  ;\n  --tw-backdrop-blur:  ;\n  --tw-backdrop-brightness:  ;\n  --tw-backdrop-contrast:  ;\n  --tw-backdrop-grayscale:  ;\n  --tw-backdrop-hue-rotate:  ;\n  --tw-backdrop-invert:  ;\n  --tw-backdrop-opacity:  ;\n  --tw-backdrop-saturate:  ;\n  --tw-backdrop-sepia:  ;\n}\n\n.sr-only {\n  position: absolute;\n  width: 1px;\n  height: 1px;\n  padding: 0;\n  margin: -1px;\n  overflow: hidden;\n  clip: rect(0, 0, 0, 0);\n  white-space: nowrap;\n  border-width: 0;\n}\n\n.absolute {\n  position: absolute;\n}\n\n.relative {\n  position: relative;\n}\n\n.col-span-6 {\n  grid-column: span 6 / span 6;\n}\n\n.m-2 {\n  margin: 0.5rem;\n}\n\n.mx-auto {\n  margin-left: auto;\n  margin-right: auto;\n}\n\n.my-auto {\n  margin-top: auto;\n  margin-bottom: auto;\n}\n\n.mx-4 {\n  margin-left: 1rem;\n  margin-right: 1rem;\n}\n\n.my-8 {\n  margin-top: 2rem;\n  margin-bottom: 2rem;\n}\n\n.my-3 {\n  margin-top: 0.75rem;\n  margin-bottom: 0.75rem;\n}\n\n.my-2 {\n  margin-top: 0.5rem;\n  margin-bottom: 0.5rem;\n}\n\n.mt-2 {\n  margin-top: 0.5rem;\n}\n\n.mb-2 {\n  margin-bottom: 0.5rem;\n}\n\n.mt-1 {\n  margin-top: 0.25rem;\n}\n\n.mb-1 {\n  margin-bottom: 0.25rem;\n}\n\n.mb-6 {\n  margin-bottom: 1.5rem;\n}\n\n.mt-auto {\n  margin-top: auto;\n}\n\n.mb-5 {\n  margin-bottom: 1.25rem;\n}\n\n.mr-auto {\n  margin-right: auto;\n}\n\n.mr-2 {\n  margin-right: 0.5rem;\n}\n\n.ml-2 {\n  margin-left: 0.5rem;\n}\n\n.ml-4 {\n  margin-left: 1rem;\n}\n\n.mr-4 {\n  margin-right: 1rem;\n}\n\n.mb-0 {\n  margin-bottom: 0px;\n}\n\n.mb-4 {\n  margin-bottom: 1rem;\n}\n\n.ml-auto {\n  margin-left: auto;\n}\n\n.mt-\\[6px\\] {\n  margin-top: 6px;\n}\n\n.mt-\\[5px\\] {\n  margin-top: 5px;\n}\n\n.mb-3 {\n  margin-bottom: 0.75rem;\n}\n\n.mt-3 {\n  margin-top: 0.75rem;\n}\n\n.mt-5 {\n  margin-top: 1.25rem;\n}\n\n.block {\n  display: block;\n}\n\n.flex {\n  display: flex;\n}\n\n.inline-flex {\n  display: inline-flex;\n}\n\n.table {\n  display: table;\n}\n\n.grid {\n  display: grid;\n}\n\n.hidden {\n  display: none;\n}\n\n.h-screen {\n  height: 100vh;\n}\n\n.w-screen {\n  width: 100vw;\n}\n\n.w-full {\n  width: 100%;\n}\n\n.w-auto {\n  width: auto;\n}\n\n.w-16 {\n  width: 4rem;\n}\n\n.max-w-sm {\n  max-width: 24rem;\n}\n\n.border-collapse {\n  border-collapse: collapse;\n}\n\n.grid-cols-2 {\n  grid-template-columns: repeat(2, minmax(0, 1fr));\n}\n\n.flex-row {\n  flex-direction: row;\n}\n\n.flex-col {\n  flex-direction: column;\n}\n\n.content-center {\n  align-content: center;\n}\n\n.items-center {\n  align-items: center;\n}\n\n.justify-center {\n  justify-content: center;\n}\n\n.space-y-0 > :not([hidden]) ~ :not([hidden]) {\n  --tw-space-y-reverse: 0;\n  margin-top: calc(0px * (1 - var(--tw-space-y-reverse)));\n  margin-top: calc(0px * calc(1 - var(--tw-space-y-reverse)));\n  margin-bottom: calc(0px * var(--tw-space-y-reverse));\n}\n\n.overflow-hidden {\n  overflow: hidden;\n}\n\n.overflow-x-auto {\n  overflow-x: auto;\n}\n\n.rounded-lg {\n  border-radius: 0.5rem;\n}\n\n.rounded-none {\n  border-radius: 0px;\n}\n\n.rounded-b-md {\n  border-bottom-right-radius: 0.375rem;\n  border-bottom-left-radius: 0.375rem;\n}\n\n.border {\n  border-width: 1px;\n}\n\n.border-b {\n  border-bottom-width: 1px;\n}\n\n.border-transparent {\n  border-color: transparent;\n}\n\n.border-neutral-100 {\n  --tw-border-opacity: 1;\n  border-color: rgba(245, 245, 245, var(--tw-border-opacity));\n}\n\n.border-neutral-200 {\n  --tw-border-opacity: 1;\n  border-color: rgba(229, 229, 229, var(--tw-border-opacity));\n}\n\n.border-white {\n  --tw-border-opacity: 1;\n  border-color: rgba(255, 255, 255, var(--tw-border-opacity));\n}\n\n.border-gray-300 {\n  --tw-border-opacity: 1;\n  border-color: rgba(209, 213, 219, var(--tw-border-opacity));\n}\n\n.bg-white {\n  --tw-bg-opacity: 1;\n  background-color: rgba(255, 255, 255, var(--tw-bg-opacity));\n}\n\n.bg-blue-500 {\n  --tw-bg-opacity: 1;\n  background-color: rgba(59, 130, 246, var(--tw-bg-opacity));\n}\n\n.bg-gray-50 {\n  --tw-bg-opacity: 1;\n  background-color: rgba(249, 250, 251, var(--tw-bg-opacity));\n}\n\n.bg-blue-600 {\n  --tw-bg-opacity: 1;\n  background-color: rgba(37, 99, 235, var(--tw-bg-opacity));\n}\n\n.bg-neutral-100 {\n  --tw-bg-opacity: 1;\n  background-color: rgba(245, 245, 245, var(--tw-bg-opacity));\n}\n\n.bg-gradient-to-br {\n  background-image: linear-gradient(to bottom right, var(--tw-gradient-stops));\n}\n\n.from-pink-500 {\n  --tw-gradient-from: #ec4899;\n  --tw-gradient-to: rgba(236, 72, 153, 0);\n  --tw-gradient-stops: var(--tw-gradient-from), var(--tw-gradient-to);\n}\n\n.from-violet-500 {\n  --tw-gradient-from: #8b5cf6;\n  --tw-gradient-to: rgba(139, 92, 246, 0);\n  --tw-gradient-stops: var(--tw-gradient-from), var(--tw-gradient-to);\n}\n\n.from-neutral-600 {\n  --tw-gradient-from: #525252;\n  --tw-gradient-to: rgba(82, 82, 82, 0);\n  --tw-gradient-stops: var(--tw-gradient-from), var(--tw-gradient-to);\n}\n\n.from-green-500 {\n  --tw-gradient-from: #22c55e;\n  --tw-gradient-to: rgba(34, 197, 94, 0);\n  --tw-gradient-stops: var(--tw-gradient-from), var(--tw-gradient-to);\n}\n\n.from-blue-500 {\n  --tw-gradient-from: #3b82f6;\n  --tw-gradient-to: rgba(59, 130, 246, 0);\n  --tw-gradient-stops: var(--tw-gradient-from), var(--tw-gradient-to);\n}\n\n.from-red-500 {\n  --tw-gradient-from: #ef4444;\n  --tw-gradient-to: rgba(239, 68, 68, 0);\n  --tw-gradient-stops: var(--tw-gradient-from), var(--tw-gradient-to);\n}\n\n.to-pink-300 {\n  --tw-gradient-to: #f9a8d4;\n}\n\n.to-violet-300 {\n  --tw-gradient-to: #c4b5fd;\n}\n\n.to-neutral-400 {\n  --tw-gradient-to: #a3a3a3;\n}\n\n.to-green-300 {\n  --tw-gradient-to: #86efac;\n}\n\n.to-blue-300 {\n  --tw-gradient-to: #93c5fd;\n}\n\n.to-red-300 {\n  --tw-gradient-to: #fca5a5;\n}\n\n.p-2 {\n  padding: 0.5rem;\n}\n\n.px-6 {\n  padding-left: 1.5rem;\n  padding-right: 1.5rem;\n}\n\n.py-4 {\n  padding-top: 1rem;\n  padding-bottom: 1rem;\n}\n\n.px-4 {\n  padding-left: 1rem;\n  padding-right: 1rem;\n}\n\n.py-5 {\n  padding-top: 1.25rem;\n  padding-bottom: 1.25rem;\n}\n\n.py-2 {\n  padding-top: 0.5rem;\n  padding-bottom: 0.5rem;\n}\n\n.py-20 {\n  padding-top: 5rem;\n  padding-bottom: 5rem;\n}\n\n.py-\\[6px\\] {\n  padding-top: 6px;\n  padding-bottom: 6px;\n}\n\n.px-0 {\n  padding-left: 0px;\n  padding-right: 0px;\n}\n\n.px-3 {\n  padding-left: 0.75rem;\n  padding-right: 0.75rem;\n}\n\n.py-1 {\n  padding-top: 0.25rem;\n  padding-bottom: 0.25rem;\n}\n\n.py-\\[8px\\] {\n  padding-top: 8px;\n  padding-bottom: 8px;\n}\n\n.px-8 {\n  padding-left: 2rem;\n  padding-right: 2rem;\n}\n\n.py-\\[2px\\] {\n  padding-top: 2px;\n  padding-bottom: 2px;\n}\n\n.px-5 {\n  padding-left: 1.25rem;\n  padding-right: 1.25rem;\n}\n\n.pr-3 {\n  padding-right: 0.75rem;\n}\n\n.pr-4 {\n  padding-right: 1rem;\n}\n\n.text-right {\n  text-align: right;\n}\n\n.text-2xl {\n  font-size: 1.5rem;\n  line-height: 2rem;\n}\n\n.text-sm {\n  font-size: 0.875rem;\n  line-height: 1.25rem;\n}\n\n.text-lg {\n  font-size: 1.125rem;\n  line-height: 1.75rem;\n}\n\n.font-semibold {\n  font-weight: 600;\n}\n\n.font-medium {\n  font-weight: 500;\n}\n\n.font-bold {\n  font-weight: 700;\n}\n\n.leading-6 {\n  line-height: 1.5rem;\n}\n\n.text-white {\n  --tw-text-opacity: 1;\n  color: rgba(255, 255, 255, var(--tw-text-opacity));\n}\n\n.text-neutral-100 {\n  --tw-text-opacity: 1;\n  color: rgba(245, 245, 245, var(--tw-text-opacity));\n}\n\n.text-neutral-600 {\n  --tw-text-opacity: 1;\n  color: rgba(82, 82, 82, var(--tw-text-opacity));\n}\n\n.text-blue-500 {\n  --tw-text-opacity: 1;\n  color: rgba(59, 130, 246, var(--tw-text-opacity));\n}\n\n.text-gray-900 {\n  --tw-text-opacity: 1;\n  color: rgba(17, 24, 39, var(--tw-text-opacity));\n}\n\n.text-gray-700 {\n  --tw-text-opacity: 1;\n  color: rgba(55, 65, 81, var(--tw-text-opacity));\n}\n\n.text-gray-500 {\n  --tw-text-opacity: 1;\n  color: rgba(107, 114, 128, var(--tw-text-opacity));\n}\n\n.shadow-sm {\n  --tw-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.05);\n  --tw-shadow-colored: 0 1px 2px 0 var(--tw-shadow-color);\n  box-shadow: 0 0 rgba(0,0,0,0), 0 0 rgba(0,0,0,0), var(--tw-shadow);\n  box-shadow: 0 0 rgba(0,0,0,0), 0 0 rgba(0,0,0,0), var(--tw-shadow);\n  box-shadow: var(--tw-ring-offset-shadow, 0 0 rgba(0,0,0,0)), var(--tw-ring-shadow, 0 0 rgba(0,0,0,0)), var(--tw-shadow);\n}\n\n.shadow-lg {\n  --tw-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -4px rgba(0, 0, 0, 0.1);\n  --tw-shadow-colored: 0 10px 15px -3px var(--tw-shadow-color), 0 4px 6px -4px var(--tw-shadow-color);\n  box-shadow: 0 0 rgba(0,0,0,0), 0 0 rgba(0,0,0,0), var(--tw-shadow);\n  box-shadow: 0 0 rgba(0,0,0,0), 0 0 rgba(0,0,0,0), var(--tw-shadow);\n  box-shadow: var(--tw-ring-offset-shadow, 0 0 rgba(0,0,0,0)), var(--tw-ring-shadow, 0 0 rgba(0,0,0,0)), var(--tw-shadow);\n}\n\n.shadow {\n  --tw-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1), 0 1px 2px -1px rgba(0, 0, 0, 0.1);\n  --tw-shadow-colored: 0 1px 3px 0 var(--tw-shadow-color), 0 1px 2px -1px var(--tw-shadow-color);\n  box-shadow: 0 0 rgba(0,0,0,0), 0 0 rgba(0,0,0,0), var(--tw-shadow);\n  box-shadow: 0 0 rgba(0,0,0,0), 0 0 rgba(0,0,0,0), var(--tw-shadow);\n  box-shadow: var(--tw-ring-offset-shadow, 0 0 rgba(0,0,0,0)), var(--tw-ring-shadow, 0 0 rgba(0,0,0,0)), var(--tw-shadow);\n}\n\n.outline-none {\n  outline: 2px solid transparent;\n  outline-offset: 2px;\n}\n\n.font-jost {\n  font-family: \"Jost\";\n}\n\n.font-inter {\n  font-family: \"Inter\";\n}\n\n.code {\n  font-family: \"Source Code Pro\", monospace;\n  display: block;\n  background-color: white;\n  color: #000000;\n  padding: 1em;\n  word-wrap: break-word;\n  white-space: pre-wrap;\n}\n\n.sidenav {\n  height: 100%;\n  /* 100% Full-height */\n  width: 0;\n  /* 0 width - change this with JavaScript */\n  position: fixed;\n  /* Stay in place */\n  z-index: 1;\n  /* Stay on top */\n  top: 0;\n  /* Stay at the top */\n  left: 0;\n  overflow-x: hidden;\n  /* Disable horizontal scroll */\n  padding-top: 60px;\n  /* Place content 60px from the top */\n  transition: 0.5s;\n  /* 0.5 second transition effect to slide in the sidenav */\n}\n\n/* The navigation menu links */\n\n.sidenav a {\n  display: block;\n}\n\nselect {\n  -webkit-appearance: none;\n     -moz-appearance: none;\n          appearance: none;\n  background-color: #fff;\n  border-color: #6b7280;\n  border-width: 1px;\n  border-radius: 0px;\n  padding-top: 0.5rem;\n  padding-right: 0.75rem;\n  padding-bottom: 0.5rem;\n  padding-left: 0.75rem;\n  font-size: 1rem;\n  line-height: 1.5rem;\n  --tw-shadow: 0 0 rgba(0,0,0,0);\n}\n\n select:focus {\n  outline: 2px solid transparent;\n  outline-offset: 2px;\n  --tw-ring-inset: var(--tw-empty,/*!*/ /*!*/);\n  --tw-ring-offset-width: 0px;\n  --tw-ring-offset-color: #fff;\n  --tw-ring-color: #2563eb;\n  --tw-ring-offset-shadow: var(--tw-ring-inset) 0 0 0 var(--tw-ring-offset-width) var(--tw-ring-offset-color);\n  --tw-ring-shadow: var(--tw-ring-inset) 0 0 0 calc(1px + var(--tw-ring-offset-width)) var(--tw-ring-color);\n  box-shadow: var(--tw-ring-offset-shadow), var(--tw-ring-shadow), var(--tw-shadow);\n  border-color: #2563eb;\n}\n\nselect {\n  background-image: url(" +
            p +
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
        const b = u;
      },
      645: (n) => {
        "use strict";
        n.exports = function (n) {
          var e = [];
          return (
            (e.toString = function () {
              return this.map(function (e) {
                var t = "",
                  r = void 0 !== e[5];
                return (
                  e[4] && (t += "@supports (".concat(e[4], ") {")),
                  e[2] && (t += "@media ".concat(e[2], " {")),
                  r &&
                    (t += "@layer".concat(
                      e[5].length > 0 ? " ".concat(e[5]) : "",
                      " {"
                    )),
                  (t += n(e)),
                  r && (t += "}"),
                  e[2] && (t += "}"),
                  e[4] && (t += "}"),
                  t
                );
              }).join("");
            }),
            (e.i = function (n, t, r, o, i) {
              "string" == typeof n && (n = [[null, n, void 0]]);
              var s = {};
              if (r)
                for (var a = 0; a < this.length; a++) {
                  var A = this[a][0];
                  null != A && (s[A] = !0);
                }
              for (var c = 0; c < n.length; c++) {
                var d = [].concat(n[c]);
                (r && s[d[0]]) ||
                  (void 0 !== i &&
                    (void 0 === d[5] ||
                      (d[1] = "@layer"
                        .concat(d[5].length > 0 ? " ".concat(d[5]) : "", " {")
                        .concat(d[1], "}")),
                    (d[5] = i)),
                  t &&
                    (d[2]
                      ? ((d[1] = "@media "
                          .concat(d[2], " {")
                          .concat(d[1], "}")),
                        (d[2] = t))
                      : (d[2] = t)),
                  o &&
                    (d[4]
                      ? ((d[1] = "@supports ("
                          .concat(d[4], ") {")
                          .concat(d[1], "}")),
                        (d[4] = o))
                      : (d[4] = "".concat(o))),
                  e.push(d));
              }
            }),
            e
          );
        };
      },
      667: (n) => {
        "use strict";
        n.exports = function (n, e) {
          return (
            e || (e = {}),
            n
              ? ((n = String(n.__esModule ? n.default : n)),
                /^['"].*['"]$/.test(n) && (n = n.slice(1, -1)),
                e.hash && (n += e.hash),
                /["'() \t\n]|(%20)/.test(n) || e.needQuotes
                  ? '"'.concat(
                      n.replace(/"/g, '\\"').replace(/\n/g, "\\n"),
                      '"'
                    )
                  : n)
              : n
          );
        };
      },
      537: (n) => {
        "use strict";
        n.exports = function (n) {
          var e = n[1],
            t = n[3];
          if (!t) return e;
          if ("function" == typeof btoa) {
            var r = btoa(unescape(encodeURIComponent(JSON.stringify(t)))),
              o =
                "sourceMappingURL=data:application/json;charset=utf-8;base64,".concat(
                  r
                ),
              i = "/*# ".concat(o, " */"),
              s = t.sources.map(function (n) {
                return "/*# sourceURL="
                  .concat(t.sourceRoot || "")
                  .concat(n, " */");
              });
            return [e].concat(s).concat([i]).join("\n");
          }
          return [e].join("\n");
        };
      },
      284: (n) => {
        var e = function () {
          if ("object" == typeof self && self) return self;
          if ("object" == typeof window && window) return window;
          throw new Error("Unable to resolve global `this`");
        };
        n.exports = (function () {
          if (this) return this;
          if ("object" == typeof globalThis && globalThis) return globalThis;
          try {
            Object.defineProperty(Object.prototype, "__global__", {
              get: function () {
                return this;
              },
              configurable: !0,
            });
          } catch (n) {
            return e();
          }
          try {
            return __global__ || e();
          } finally {
            delete Object.prototype.__global__;
          }
        })();
      },
      379: (n) => {
        "use strict";
        var e = [];
        function t(n) {
          for (var t = -1, r = 0; r < e.length; r++)
            if (e[r].identifier === n) {
              t = r;
              break;
            }
          return t;
        }
        function r(n, r) {
          for (var i = {}, s = [], a = 0; a < n.length; a++) {
            var A = n[a],
              c = r.base ? A[0] + r.base : A[0],
              d = i[c] || 0,
              l = "".concat(c, " ").concat(d);
            i[c] = d + 1;
            var h = t(l),
              u = {
                css: A[1],
                media: A[2],
                sourceMap: A[3],
                supports: A[4],
                layer: A[5],
              };
            if (-1 !== h) e[h].references++, e[h].updater(u);
            else {
              var p = o(u, r);
              (r.byIndex = a),
                e.splice(a, 0, { identifier: l, updater: p, references: 1 });
            }
            s.push(l);
          }
          return s;
        }
        function o(n, e) {
          var t = e.domAPI(e);
          return (
            t.update(n),
            function (e) {
              if (e) {
                if (
                  e.css === n.css &&
                  e.media === n.media &&
                  e.sourceMap === n.sourceMap &&
                  e.supports === n.supports &&
                  e.layer === n.layer
                )
                  return;
                t.update((n = e));
              } else t.remove();
            }
          );
        }
        n.exports = function (n, o) {
          var i = r((n = n || []), (o = o || {}));
          return function (n) {
            n = n || [];
            for (var s = 0; s < i.length; s++) {
              var a = t(i[s]);
              e[a].references--;
            }
            for (var A = r(n, o), c = 0; c < i.length; c++) {
              var d = t(i[c]);
              0 === e[d].references && (e[d].updater(), e.splice(d, 1));
            }
            i = A;
          };
        };
      },
      569: (n) => {
        "use strict";
        var e = {};
        n.exports = function (n, t) {
          var r = (function (n) {
            if (void 0 === e[n]) {
              var t = document.querySelector(n);
              if (
                window.HTMLIFrameElement &&
                t instanceof window.HTMLIFrameElement
              )
                try {
                  t = t.contentDocument.head;
                } catch (n) {
                  t = null;
                }
              e[n] = t;
            }
            return e[n];
          })(n);
          if (!r)
            throw new Error(
              "Couldn't find a style target. This probably means that the value for the 'insert' parameter is invalid."
            );
          r.appendChild(t);
        };
      },
      216: (n) => {
        "use strict";
        n.exports = function (n) {
          var e = document.createElement("style");
          return n.setAttributes(e, n.attributes), n.insert(e, n.options), e;
        };
      },
      565: (n, e, t) => {
        "use strict";
        n.exports = function (n) {
          var e = t.nc;
          e && n.setAttribute("nonce", e);
        };
      },
      795: (n) => {
        "use strict";
        n.exports = function (n) {
          var e = n.insertStyleElement(n);
          return {
            update: function (t) {
              !(function (n, e, t) {
                var r = "";
                t.supports && (r += "@supports (".concat(t.supports, ") {")),
                  t.media && (r += "@media ".concat(t.media, " {"));
                var o = void 0 !== t.layer;
                o &&
                  (r += "@layer".concat(
                    t.layer.length > 0 ? " ".concat(t.layer) : "",
                    " {"
                  )),
                  (r += t.css),
                  o && (r += "}"),
                  t.media && (r += "}"),
                  t.supports && (r += "}");
                var i = t.sourceMap;
                i &&
                  "undefined" != typeof btoa &&
                  (r +=
                    "\n/*# sourceMappingURL=data:application/json;base64,".concat(
                      btoa(unescape(encodeURIComponent(JSON.stringify(i)))),
                      " */"
                    )),
                  e.styleTagTransform(r, n, e.options);
              })(e, n, t);
            },
            remove: function () {
              !(function (n) {
                if (null === n.parentNode) return !1;
                n.parentNode.removeChild(n);
              })(e);
            },
          };
        };
      },
      589: (n) => {
        "use strict";
        n.exports = function (n, e) {
          if (e.styleSheet) e.styleSheet.cssText = n;
          else {
            for (; e.firstChild; ) e.removeChild(e.firstChild);
            e.appendChild(document.createTextNode(n));
          }
        };
      },
      840: (n, e, t) => {
        var r;
        if ("object" == typeof globalThis) r = globalThis;
        else
          try {
            r = t(284);
          } catch (n) {
          } finally {
            if ((r || "undefined" == typeof window || (r = window), !r))
              throw new Error("Could not determine global this");
          }
        var o = r.WebSocket || r.MozWebSocket,
          i = t(387);
        function s(n, e) {
          return e ? new o(n, e) : new o(n);
        }
        o &&
          ["CONNECTING", "OPEN", "CLOSING", "CLOSED"].forEach(function (n) {
            Object.defineProperty(s, n, {
              get: function () {
                return o[n];
              },
            });
          }),
          (n.exports = { w3cwebsocket: o ? s : null, version: i });
      },
      387: (n, e, t) => {
        n.exports = t(794).version;
      },
      601: (n) => {
        "use strict";
        n.exports =
          "data:image/svg+xml,%3csvg viewBox=%270 0 16 16%27 fill=%27white%27 xmlns=%27http://www.w3.org/2000/svg%27%3e%3ccircle cx=%278%27 cy=%278%27 r=%273%27/%3e%3c/svg%3e";
      },
      133: (n) => {
        "use strict";
        n.exports =
          "data:image/svg+xml,%3csvg viewBox=%270 0 16 16%27 fill=%27white%27 xmlns=%27http://www.w3.org/2000/svg%27%3e%3cpath d=%27M12.207 4.793a1 1 0 010 1.414l-5 5a1 1 0 01-1.414 0l-2-2a1 1 0 011.414-1.414L6.5 9.086l4.293-4.293a1 1 0 011.414 0z%27/%3e%3c/svg%3e";
      },
      686: (n) => {
        "use strict";
        n.exports =
          "data:image/svg+xml,%3csvg xmlns=%27http://www.w3.org/2000/svg%27 fill=%27none%27 viewBox=%270 0 16 16%27%3e%3cpath stroke=%27white%27 stroke-linecap=%27round%27 stroke-linejoin=%27round%27 stroke-width=%272%27 d=%27M4 8h8%27/%3e%3c/svg%3e";
      },
      909: (n) => {
        "use strict";
        n.exports =
          "data:image/svg+xml,%3csvg xmlns=%27http://www.w3.org/2000/svg%27 fill=%27none%27 viewBox=%270 0 20 20%27%3e%3cpath stroke=%27%236b7280%27 stroke-linecap=%27round%27 stroke-linejoin=%27round%27 stroke-width=%271.5%27 d=%27M6 8l4 4 4-4%27/%3e%3c/svg%3e";
      },
      794: (n) => {
        "use strict";
        n.exports = { version: "1.0.34" };
      },
    },
    i = {};
  function s(n) {
    var e = i[n];
    if (void 0 !== e) return e.exports;
    var t = (i[n] = { id: n, exports: {} });
    return o[n].call(t.exports, t, t.exports, s), t.exports;
  }
  (s.m = o),
    (s.n = (n) => {
      var e = n && n.__esModule ? () => n.default : () => n;
      return s.d(e, { a: e }), e;
    }),
    (e = Object.getPrototypeOf
      ? (n) => Object.getPrototypeOf(n)
      : (n) => n.__proto__),
    (s.t = function (t, r) {
      if ((1 & r && (t = this(t)), 8 & r)) return t;
      if ("object" == typeof t && t) {
        if (4 & r && t.__esModule) return t;
        if (16 & r && "function" == typeof t.then) return t;
      }
      var o = Object.create(null);
      s.r(o);
      var i = {};
      n = n || [null, e({}), e([]), e(e)];
      for (var a = 2 & r && t; "object" == typeof a && !~n.indexOf(a); a = e(a))
        Object.getOwnPropertyNames(a).forEach((n) => (i[n] = () => t[n]));
      return (i.default = () => t), s.d(o, i), o;
    }),
    (s.d = (n, e) => {
      for (var t in e)
        s.o(e, t) &&
          !s.o(n, t) &&
          Object.defineProperty(n, t, { enumerable: !0, get: e[t] });
    }),
    (s.f = {}),
    (s.e = (n) =>
      Promise.all(Object.keys(s.f).reduce((e, t) => (s.f[t](n, e), e), []))),
    (s.u = (n) => n + ".js"),
    (s.g = (function () {
      if ("object" == typeof globalThis) return globalThis;
      try {
        return this || new Function("return this")();
      } catch (n) {
        if ("object" == typeof window) return window;
      }
    })()),
    (s.o = (n, e) => Object.prototype.hasOwnProperty.call(n, e)),
    (t = {}),
    (r = "tts:"),
    (s.l = (n, e, o, i) => {
      if (t[n]) t[n].push(e);
      else {
        var a, A;
        if (void 0 !== o)
          for (
            var c = document.getElementsByTagName("script"), d = 0;
            d < c.length;
            d++
          ) {
            var l = c[d];
            if (
              l.getAttribute("src") == n ||
              l.getAttribute("data-webpack") == r + o
            ) {
              a = l;
              break;
            }
          }
        a ||
          ((A = !0),
          ((a = document.createElement("script")).charset = "utf-8"),
          (a.timeout = 120),
          s.nc && a.setAttribute("nonce", s.nc),
          a.setAttribute("data-webpack", r + o),
          (a.src = n)),
          (t[n] = [e]);
        var h = (e, r) => {
            (a.onerror = a.onload = null), clearTimeout(u);
            var o = t[n];
            if (
              (delete t[n],
              a.parentNode && a.parentNode.removeChild(a),
              o && o.forEach((n) => n(r)),
              e)
            )
              return e(r);
          },
          u = setTimeout(
            h.bind(null, void 0, { type: "timeout", target: a }),
            12e4
          );
        (a.onerror = h.bind(null, a.onerror)),
          (a.onload = h.bind(null, a.onload)),
          A && document.head.appendChild(a);
      }
    }),
    (s.r = (n) => {
      "undefined" != typeof Symbol &&
        Symbol.toStringTag &&
        Object.defineProperty(n, Symbol.toStringTag, { value: "Module" }),
        Object.defineProperty(n, "__esModule", { value: !0 });
    }),
    (() => {
      var n;
      s.g.importScripts && (n = s.g.location + "");
      var e = s.g.document;
      if (!n && e && (e.currentScript && (n = e.currentScript.src), !n)) {
        var t = e.getElementsByTagName("script");
        t.length && (n = t[t.length - 1].src);
      }
      if (!n)
        throw new Error(
          "Automatic publicPath is not supported in this browser"
        );
      (n = n
        .replace(/#.*$/, "")
        .replace(/\?.*$/, "")
        .replace(/\/[^\/]+$/, "/")),
        (s.p = n);
    })(),
    (() => {
      s.b = document.baseURI || self.location.href;
      var n = { 650: 0 };
      s.f.j = (e, t) => {
        var r = s.o(n, e) ? n[e] : void 0;
        if (0 !== r)
          if (r) t.push(r[2]);
          else {
            var o = new Promise((t, o) => (r = n[e] = [t, o]));
            t.push((r[2] = o));
            var i = s.p + s.u(e),
              a = new Error();
            s.l(
              i,
              (t) => {
                if (s.o(n, e) && (0 !== (r = n[e]) && (n[e] = void 0), r)) {
                  var o = t && ("load" === t.type ? "missing" : t.type),
                    i = t && t.target && t.target.src;
                  (a.message =
                    "Loading chunk " + e + " failed.\n(" + o + ": " + i + ")"),
                    (a.name = "ChunkLoadError"),
                    (a.type = o),
                    (a.request = i),
                    r[1](a);
                }
              },
              "chunk-" + e,
              e
            );
          }
      };
      var e = (e, t) => {
          var r,
            o,
            [i, a, A] = t,
            c = 0;
          if (i.some((e) => 0 !== n[e])) {
            for (r in a) s.o(a, r) && (s.m[r] = a[r]);
            A && A(s);
          }
          for (e && e(t); c < i.length; c++)
            (o = i[c]), s.o(n, o) && n[o] && n[o][0](), (n[o] = 0);
        },
        t = (self.webpackChunktts = self.webpackChunktts || []);
      t.forEach(e.bind(null, 0)), (t.push = e.bind(null, t.push.bind(t)));
    })(),
    (s.nc = void 0),
    (() => {
      "use strict";
      const n = { "X-Client-Info": "supabase-js/1.35.6" },
        e = "Request Failed",
        t = "supabase.auth.token",
        r = {
          name: "sb",
          lifetime: 28800,
          domain: "",
          path: "/",
          sameSite: "lax",
        };
      var o = function (n, e, t, r) {
        return new (t || (t = Promise))(function (o, i) {
          function s(n) {
            try {
              A(r.next(n));
            } catch (n) {
              i(n);
            }
          }
          function a(n) {
            try {
              A(r.throw(n));
            } catch (n) {
              i(n);
            }
          }
          function A(n) {
            var e;
            n.done
              ? o(n.value)
              : ((e = n.value),
                e instanceof t
                  ? e
                  : new t(function (n) {
                      n(e);
                    })).then(s, a);
          }
          A((r = r.apply(n, e || [])).next());
        });
      };
      const i = (n) =>
        n.msg ||
        n.message ||
        n.error_description ||
        n.error ||
        JSON.stringify(n);
      function a(n, t, r, s, a) {
        return o(this, void 0, void 0, function* () {
          return new Promise((o, A) => {
            n(
              r,
              ((n, e, t) => {
                const r = {
                  method: n,
                  headers: (null == e ? void 0 : e.headers) || {},
                };
                return (
                  "GET" === n ||
                    ((r.headers = Object.assign(
                      { "Content-Type": "text/plain;charset=UTF-8" },
                      null == e ? void 0 : e.headers
                    )),
                    (r.body = JSON.stringify(t))),
                  r
                );
              })(t, s, a)
            )
              .then((n) => {
                if (!n.ok) throw n;
                return (null == s ? void 0 : s.noResolveJson) ? o : n.json();
              })
              .then((n) => o(n))
              .catch((n) =>
                ((n, t) =>
                  (null == n ? void 0 : n.status)
                    ? "function" != typeof n.json
                      ? t(n)
                      : void n
                          .json()
                          .then((e) =>
                            t({
                              message: i(e),
                              status: (null == n ? void 0 : n.status) || 500,
                            })
                          )
                    : t({ message: e }))(n, A)
              );
          });
        });
      }
      function A(n, e, t) {
        return o(this, void 0, void 0, function* () {
          return a(n, "GET", e, t);
        });
      }
      function c(n, e, t, r) {
        return o(this, void 0, void 0, function* () {
          return a(n, "POST", e, r, t);
        });
      }
      function d(n, e, t, r) {
        return o(this, void 0, void 0, function* () {
          return a(n, "PUT", e, r, t);
        });
      }
      function l(n, e, t) {
        const r = t.map((e) => {
            return (
              (t = e),
              (r = (function (n) {
                if (!n || !n.headers || !n.headers.host)
                  throw new Error('The "host" request header is not available');
                const e =
                  (n.headers.host.indexOf(":") > -1 &&
                    n.headers.host.split(":")[0]) ||
                  n.headers.host;
                return !(
                  ["localhost", "127.0.0.1"].indexOf(e) > -1 ||
                  e.endsWith(".local")
                );
              })(n)),
              (function (n, e, t) {
                const r = t || {},
                  o = encodeURIComponent,
                  i = /^[\u0009\u0020-\u007e\u0080-\u00ff]+$/;
                if ("function" != typeof o)
                  throw new TypeError("option encode is invalid");
                if (!i.test(n)) throw new TypeError("argument name is invalid");
                const s = o(e);
                if (s && !i.test(s))
                  throw new TypeError("argument val is invalid");
                let a = n + "=" + s;
                if (null != r.maxAge) {
                  const n = r.maxAge - 0;
                  if (isNaN(n) || !isFinite(n))
                    throw new TypeError("option maxAge is invalid");
                  a += "; Max-Age=" + Math.floor(n);
                }
                if (r.domain) {
                  if (!i.test(r.domain))
                    throw new TypeError("option domain is invalid");
                  a += "; Domain=" + r.domain;
                }
                if (r.path) {
                  if (!i.test(r.path))
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
                path: null !== (o = t.path) && void 0 !== o ? o : "/",
                domain: null !== (i = t.domain) && void 0 !== i ? i : "",
                sameSite: null !== (s = t.sameSite) && void 0 !== s ? s : "lax",
              })
            );
            var t, r, o, i, s;
          }),
          o = e.getHeader("Set-Cookie");
        return (
          o &&
            (o instanceof Array
              ? Array.prototype.push.apply(r, o)
              : "string" == typeof o && r.push(o)),
          r
        );
      }
      function h(n, e, t) {
        e.setHeader("Set-Cookie", l(n, e, t));
      }
      var u = function (n, e, t, r) {
        return new (t || (t = Promise))(function (o, i) {
          function s(n) {
            try {
              A(r.next(n));
            } catch (n) {
              i(n);
            }
          }
          function a(n) {
            try {
              A(r.throw(n));
            } catch (n) {
              i(n);
            }
          }
          function A(n) {
            var e;
            n.done
              ? o(n.value)
              : ((e = n.value),
                e instanceof t
                  ? e
                  : new t(function (n) {
                      n(e);
                    })).then(s, a);
          }
          A((r = r.apply(n, e || [])).next());
        });
      };
      function p(n) {
        return Math.round(Date.now() / 1e3) + n;
      }
      const g = () => "undefined" != typeof window;
      function m(n, e) {
        var t;
        e ||
          (e =
            (null ===
              (t =
                null === window || void 0 === window
                  ? void 0
                  : window.location) || void 0 === t
              ? void 0
              : t.href) || ""),
          (n = n.replace(/[\[\]]/g, "\\$&"));
        const r = new RegExp("[?&#]" + n + "(=([^&#]*)|&|#|$)").exec(e);
        return r
          ? r[2]
            ? decodeURIComponent(r[2].replace(/\+/g, " "))
            : ""
          : null;
      }
      const f = (n) => {
        let e;
        return (
          (e =
            n ||
            ("undefined" == typeof fetch
              ? (...n) =>
                  u(void 0, void 0, void 0, function* () {
                    return yield (yield s
                      .e(98)
                      .then(s.t.bind(s, 98, 23))).fetch(...n);
                  })
              : fetch)),
          (...n) => e(...n)
        );
      };
      var b = function (n, e, t, r) {
        return new (t || (t = Promise))(function (o, i) {
          function s(n) {
            try {
              A(r.next(n));
            } catch (n) {
              i(n);
            }
          }
          function a(n) {
            try {
              A(r.throw(n));
            } catch (n) {
              i(n);
            }
          }
          function A(n) {
            var e;
            n.done
              ? o(n.value)
              : ((e = n.value),
                e instanceof t
                  ? e
                  : new t(function (n) {
                      n(e);
                    })).then(s, a);
          }
          A((r = r.apply(n, e || [])).next());
        });
      };
      class w {
        constructor({
          url: n = "",
          headers: e = {},
          cookieOptions: t,
          fetch: o,
        }) {
          (this.url = n),
            (this.headers = e),
            (this.cookieOptions = Object.assign(Object.assign({}, r), t)),
            (this.fetch = f(o));
        }
        _createRequestHeaders(n) {
          const e = Object.assign({}, this.headers);
          return (e.Authorization = `Bearer ${n}`), e;
        }
        cookieName() {
          var n;
          return null !== (n = this.cookieOptions.name) && void 0 !== n
            ? n
            : "";
        }
        getUrlForProvider(n, e) {
          const t = [`provider=${encodeURIComponent(n)}`];
          if (
            ((null == e ? void 0 : e.redirectTo) &&
              t.push(`redirect_to=${encodeURIComponent(e.redirectTo)}`),
            (null == e ? void 0 : e.scopes) &&
              t.push(`scopes=${encodeURIComponent(e.scopes)}`),
            null == e ? void 0 : e.queryParams)
          ) {
            const n = new URLSearchParams(e.queryParams);
            t.push(`${n}`);
          }
          return `${this.url}/authorize?${t.join("&")}`;
        }
        signUpWithEmail(n, e, t = {}) {
          return b(this, void 0, void 0, function* () {
            try {
              const r = Object.assign({}, this.headers);
              let o = "";
              t.redirectTo &&
                (o = "?redirect_to=" + encodeURIComponent(t.redirectTo));
              const i = yield c(
                  this.fetch,
                  `${this.url}/signup${o}`,
                  {
                    email: n,
                    password: e,
                    data: t.data,
                    gotrue_meta_security: { captcha_token: t.captchaToken },
                  },
                  { headers: r }
                ),
                s = Object.assign({}, i);
              return (
                s.expires_in && (s.expires_at = p(i.expires_in)),
                { data: s, error: null }
              );
            } catch (n) {
              return { data: null, error: n };
            }
          });
        }
        signInWithEmail(n, e, t = {}) {
          return b(this, void 0, void 0, function* () {
            try {
              const r = Object.assign({}, this.headers);
              let o = "?grant_type=password";
              t.redirectTo &&
                (o += "&redirect_to=" + encodeURIComponent(t.redirectTo));
              const i = yield c(
                  this.fetch,
                  `${this.url}/token${o}`,
                  {
                    email: n,
                    password: e,
                    gotrue_meta_security: { captcha_token: t.captchaToken },
                  },
                  { headers: r }
                ),
                s = Object.assign({}, i);
              return (
                s.expires_in && (s.expires_at = p(i.expires_in)),
                { data: s, error: null }
              );
            } catch (n) {
              return { data: null, error: n };
            }
          });
        }
        signUpWithPhone(n, e, t = {}) {
          return b(this, void 0, void 0, function* () {
            try {
              const r = Object.assign({}, this.headers),
                o = yield c(
                  this.fetch,
                  `${this.url}/signup`,
                  {
                    phone: n,
                    password: e,
                    data: t.data,
                    gotrue_meta_security: { captcha_token: t.captchaToken },
                  },
                  { headers: r }
                ),
                i = Object.assign({}, o);
              return (
                i.expires_in && (i.expires_at = p(o.expires_in)),
                { data: i, error: null }
              );
            } catch (n) {
              return { data: null, error: n };
            }
          });
        }
        signInWithPhone(n, e, t = {}) {
          return b(this, void 0, void 0, function* () {
            try {
              const r = Object.assign({}, this.headers),
                o = "?grant_type=password",
                i = yield c(
                  this.fetch,
                  `${this.url}/token${o}`,
                  {
                    phone: n,
                    password: e,
                    gotrue_meta_security: { captcha_token: t.captchaToken },
                  },
                  { headers: r }
                ),
                s = Object.assign({}, i);
              return (
                s.expires_in && (s.expires_at = p(i.expires_in)),
                { data: s, error: null }
              );
            } catch (n) {
              return { data: null, error: n };
            }
          });
        }
        signInWithOpenIDConnect({
          id_token: n,
          nonce: e,
          client_id: t,
          issuer: r,
          provider: o,
        }) {
          return b(this, void 0, void 0, function* () {
            try {
              const i = Object.assign({}, this.headers),
                s = "?grant_type=id_token",
                a = yield c(
                  this.fetch,
                  `${this.url}/token${s}`,
                  {
                    id_token: n,
                    nonce: e,
                    client_id: t,
                    issuer: r,
                    provider: o,
                  },
                  { headers: i }
                ),
                A = Object.assign({}, a);
              return (
                A.expires_in && (A.expires_at = p(a.expires_in)),
                { data: A, error: null }
              );
            } catch (n) {
              return { data: null, error: n };
            }
          });
        }
        sendMagicLinkEmail(n, e = {}) {
          var t;
          return b(this, void 0, void 0, function* () {
            try {
              const r = Object.assign({}, this.headers);
              let o = "";
              e.redirectTo &&
                (o += "?redirect_to=" + encodeURIComponent(e.redirectTo));
              const i = null === (t = e.shouldCreateUser) || void 0 === t || t;
              return {
                data: yield c(
                  this.fetch,
                  `${this.url}/otp${o}`,
                  {
                    email: n,
                    create_user: i,
                    gotrue_meta_security: { captcha_token: e.captchaToken },
                  },
                  { headers: r }
                ),
                error: null,
              };
            } catch (n) {
              return { data: null, error: n };
            }
          });
        }
        sendMobileOTP(n, e = {}) {
          var t;
          return b(this, void 0, void 0, function* () {
            try {
              const r = null === (t = e.shouldCreateUser) || void 0 === t || t,
                o = Object.assign({}, this.headers);
              return {
                data: yield c(
                  this.fetch,
                  `${this.url}/otp`,
                  {
                    phone: n,
                    create_user: r,
                    gotrue_meta_security: { captcha_token: e.captchaToken },
                  },
                  { headers: o }
                ),
                error: null,
              };
            } catch (n) {
              return { data: null, error: n };
            }
          });
        }
        signOut(n) {
          return b(this, void 0, void 0, function* () {
            try {
              return (
                yield c(
                  this.fetch,
                  `${this.url}/logout`,
                  {},
                  { headers: this._createRequestHeaders(n), noResolveJson: !0 }
                ),
                { error: null }
              );
            } catch (n) {
              return { error: n };
            }
          });
        }
        verifyMobileOTP(n, e, t = {}) {
          return b(this, void 0, void 0, function* () {
            try {
              const r = Object.assign({}, this.headers),
                o = yield c(
                  this.fetch,
                  `${this.url}/verify`,
                  {
                    phone: n,
                    token: e,
                    type: "sms",
                    redirect_to: t.redirectTo,
                  },
                  { headers: r }
                ),
                i = Object.assign({}, o);
              return (
                i.expires_in && (i.expires_at = p(o.expires_in)),
                { data: i, error: null }
              );
            } catch (n) {
              return { data: null, error: n };
            }
          });
        }
        verifyOTP({ email: n, phone: e, token: t, type: r = "sms" }, o = {}) {
          return b(this, void 0, void 0, function* () {
            try {
              const i = Object.assign({}, this.headers),
                s = yield c(
                  this.fetch,
                  `${this.url}/verify`,
                  {
                    email: n,
                    phone: e,
                    token: t,
                    type: r,
                    redirect_to: o.redirectTo,
                  },
                  { headers: i }
                ),
                a = Object.assign({}, s);
              return (
                a.expires_in && (a.expires_at = p(s.expires_in)),
                { data: a, error: null }
              );
            } catch (n) {
              return { data: null, error: n };
            }
          });
        }
        inviteUserByEmail(n, e = {}) {
          return b(this, void 0, void 0, function* () {
            try {
              const t = Object.assign({}, this.headers);
              let r = "";
              return (
                e.redirectTo &&
                  (r += "?redirect_to=" + encodeURIComponent(e.redirectTo)),
                {
                  data: yield c(
                    this.fetch,
                    `${this.url}/invite${r}`,
                    { email: n, data: e.data },
                    { headers: t }
                  ),
                  error: null,
                }
              );
            } catch (n) {
              return { data: null, error: n };
            }
          });
        }
        resetPasswordForEmail(n, e = {}) {
          return b(this, void 0, void 0, function* () {
            try {
              const t = Object.assign({}, this.headers);
              let r = "";
              return (
                e.redirectTo &&
                  (r += "?redirect_to=" + encodeURIComponent(e.redirectTo)),
                {
                  data: yield c(
                    this.fetch,
                    `${this.url}/recover${r}`,
                    {
                      email: n,
                      gotrue_meta_security: { captcha_token: e.captchaToken },
                    },
                    { headers: t }
                  ),
                  error: null,
                }
              );
            } catch (n) {
              return { data: null, error: n };
            }
          });
        }
        refreshAccessToken(n) {
          return b(this, void 0, void 0, function* () {
            try {
              const e = yield c(
                  this.fetch,
                  `${this.url}/token?grant_type=refresh_token`,
                  { refresh_token: n },
                  { headers: this.headers }
                ),
                t = Object.assign({}, e);
              return (
                t.expires_in && (t.expires_at = p(e.expires_in)),
                { data: t, error: null }
              );
            } catch (n) {
              return { data: null, error: n };
            }
          });
        }
        setAuthCookie(n, e) {
          "POST" !== n.method &&
            (e.setHeader("Allow", "POST"),
            e.status(405).end("Method Not Allowed"));
          const { event: t, session: r } = n.body;
          if (!t) throw new Error("Auth event missing!");
          if ("SIGNED_IN" === t) {
            if (!r) throw new Error("Auth session missing!");
            h(
              n,
              e,
              [
                { key: "access-token", value: r.access_token },
                { key: "refresh-token", value: r.refresh_token },
              ].map((n) => {
                var e;
                return {
                  name: `${this.cookieName()}-${n.key}`,
                  value: n.value,
                  domain: this.cookieOptions.domain,
                  maxAge:
                    null !== (e = this.cookieOptions.lifetime) && void 0 !== e
                      ? e
                      : 0,
                  path: this.cookieOptions.path,
                  sameSite: this.cookieOptions.sameSite,
                };
              })
            );
          }
          "SIGNED_OUT" === t &&
            h(
              n,
              e,
              ["access-token", "refresh-token"].map((n) => ({
                name: `${this.cookieName()}-${n}`,
                value: "",
                maxAge: -1,
              }))
            ),
            e.status(200).json({});
        }
        deleteAuthCookie(n, e, { redirectTo: t = "/" }) {
          return (
            h(
              n,
              e,
              ["access-token", "refresh-token"].map((n) => ({
                name: `${this.cookieName()}-${n}`,
                value: "",
                maxAge: -1,
              }))
            ),
            e.redirect(307, t)
          );
        }
        getAuthCookieString(n, e) {
          "POST" !== n.method &&
            (e.setHeader("Allow", "POST"),
            e.status(405).end("Method Not Allowed"));
          const { event: t, session: r } = n.body;
          if (!t) throw new Error("Auth event missing!");
          if ("SIGNED_IN" === t) {
            if (!r) throw new Error("Auth session missing!");
            return l(
              n,
              e,
              [
                { key: "access-token", value: r.access_token },
                { key: "refresh-token", value: r.refresh_token },
              ].map((n) => {
                var e;
                return {
                  name: `${this.cookieName()}-${n.key}`,
                  value: n.value,
                  domain: this.cookieOptions.domain,
                  maxAge:
                    null !== (e = this.cookieOptions.lifetime) && void 0 !== e
                      ? e
                      : 0,
                  path: this.cookieOptions.path,
                  sameSite: this.cookieOptions.sameSite,
                };
              })
            );
          }
          return "SIGNED_OUT" === t
            ? l(
                n,
                e,
                ["access-token", "refresh-token"].map((n) => ({
                  name: `${this.cookieName()}-${n}`,
                  value: "",
                  maxAge: -1,
                }))
              )
            : e.getHeader("Set-Cookie");
        }
        generateLink(n, e, t = {}) {
          return b(this, void 0, void 0, function* () {
            try {
              return {
                data: yield c(
                  this.fetch,
                  `${this.url}/admin/generate_link`,
                  {
                    type: n,
                    email: e,
                    password: t.password,
                    data: t.data,
                    redirect_to: t.redirectTo,
                  },
                  { headers: this.headers }
                ),
                error: null,
              };
            } catch (n) {
              return { data: null, error: n };
            }
          });
        }
        createUser(n) {
          return b(this, void 0, void 0, function* () {
            try {
              const e = yield c(this.fetch, `${this.url}/admin/users`, n, {
                headers: this.headers,
              });
              return { user: e, data: e, error: null };
            } catch (n) {
              return { user: null, data: null, error: n };
            }
          });
        }
        listUsers() {
          return b(this, void 0, void 0, function* () {
            try {
              return {
                data: (yield A(this.fetch, `${this.url}/admin/users`, {
                  headers: this.headers,
                })).users,
                error: null,
              };
            } catch (n) {
              return { data: null, error: n };
            }
          });
        }
        getUserById(n) {
          return b(this, void 0, void 0, function* () {
            try {
              return {
                data: yield A(this.fetch, `${this.url}/admin/users/${n}`, {
                  headers: this.headers,
                }),
                error: null,
              };
            } catch (n) {
              return { data: null, error: n };
            }
          });
        }
        getUserByCookie(n, e) {
          return b(this, void 0, void 0, function* () {
            try {
              if (!n.cookies)
                throw new Error(
                  "Not able to parse cookies! When using Express make sure the cookie-parser middleware is in use!"
                );
              const t = n.cookies[`${this.cookieName()}-access-token`],
                r = n.cookies[`${this.cookieName()}-refresh-token`];
              if (!t) throw new Error("No cookie found!");
              const { user: o, error: i } = yield this.getUser(t);
              if (i) {
                if (!r) throw new Error("No refresh_token cookie found!");
                if (!e)
                  throw new Error(
                    "You need to pass the res object to automatically refresh the session!"
                  );
                const { data: t, error: o } = yield this.refreshAccessToken(r);
                if (o) throw o;
                if (t)
                  return (
                    h(
                      n,
                      e,
                      [
                        { key: "access-token", value: t.access_token },
                        { key: "refresh-token", value: t.refresh_token },
                      ].map((n) => {
                        var e;
                        return {
                          name: `${this.cookieName()}-${n.key}`,
                          value: n.value,
                          domain: this.cookieOptions.domain,
                          maxAge:
                            null !== (e = this.cookieOptions.lifetime) &&
                            void 0 !== e
                              ? e
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
              return { token: t, user: o, data: o, error: null };
            } catch (n) {
              return { token: null, user: null, data: null, error: n };
            }
          });
        }
        updateUserById(n, e) {
          return b(this, void 0, void 0, function* () {
            try {
              const t = yield d(this.fetch, `${this.url}/admin/users/${n}`, e, {
                headers: this.headers,
              });
              return { user: t, data: t, error: null };
            } catch (n) {
              return { user: null, data: null, error: n };
            }
          });
        }
        deleteUser(n) {
          return b(this, void 0, void 0, function* () {
            try {
              const e = yield (function (n, e, t, r) {
                return o(this, void 0, void 0, function* () {
                  return a(n, "DELETE", e, r, t);
                });
              })(
                this.fetch,
                `${this.url}/admin/users/${n}`,
                {},
                { headers: this.headers }
              );
              return { user: e, data: e, error: null };
            } catch (n) {
              return { user: null, data: null, error: n };
            }
          });
        }
        getUser(n) {
          return b(this, void 0, void 0, function* () {
            try {
              const e = yield A(this.fetch, `${this.url}/user`, {
                headers: this._createRequestHeaders(n),
              });
              return { user: e, data: e, error: null };
            } catch (n) {
              return { user: null, data: null, error: n };
            }
          });
        }
        updateUser(n, e) {
          return b(this, void 0, void 0, function* () {
            try {
              const t = yield d(this.fetch, `${this.url}/user`, e, {
                headers: this._createRequestHeaders(n),
              });
              return { user: t, data: t, error: null };
            } catch (n) {
              return { user: null, data: null, error: n };
            }
          });
        }
      }
      var E = function (n, e, t, r) {
        return new (t || (t = Promise))(function (o, i) {
          function s(n) {
            try {
              A(r.next(n));
            } catch (n) {
              i(n);
            }
          }
          function a(n) {
            try {
              A(r.throw(n));
            } catch (n) {
              i(n);
            }
          }
          function A(n) {
            var e;
            n.done
              ? o(n.value)
              : ((e = n.value),
                e instanceof t
                  ? e
                  : new t(function (n) {
                      n(e);
                    })).then(s, a);
          }
          A((r = r.apply(n, e || [])).next());
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
          } catch (n) {
            "undefined" != typeof self && (self.globalThis = self);
          }
      })();
      const B = {
        url: "http://localhost:9999",
        autoRefreshToken: !0,
        persistSession: !0,
        detectSessionInUrl: !0,
        multiTab: !0,
        headers: { "X-Client-Info": "gotrue-js/1.22.22" },
      };
      class C extends class {
        constructor(n) {
          (this.stateChangeEmitters = new Map()), (this.networkRetries = 0);
          const e = Object.assign(Object.assign({}, B), n);
          (this.currentUser = null),
            (this.currentSession = null),
            (this.autoRefreshToken = e.autoRefreshToken),
            (this.persistSession = e.persistSession),
            (this.multiTab = e.multiTab),
            (this.localStorage = e.localStorage || globalThis.localStorage),
            (this.api = new w({
              url: e.url,
              headers: e.headers,
              cookieOptions: e.cookieOptions,
              fetch: e.fetch,
            })),
            this._recoverSession(),
            this._recoverAndRefresh(),
            this._listenForMultiTabEvents(),
            this._handleVisibilityChange(),
            e.detectSessionInUrl &&
              g() &&
              m("access_token") &&
              this.getSessionFromUrl({ storeSession: !0 }).then(
                ({ error: n }) => {
                  if (n) throw new Error("Error getting session from URL.");
                }
              );
        }
        signUp({ email: n, password: e, phone: t }, r = {}) {
          return E(this, void 0, void 0, function* () {
            try {
              this._removeSession();
              const { data: o, error: i } =
                t && e
                  ? yield this.api.signUpWithPhone(t, e, {
                      data: r.data,
                      captchaToken: r.captchaToken,
                    })
                  : yield this.api.signUpWithEmail(n, e, {
                      redirectTo: r.redirectTo,
                      data: r.data,
                      captchaToken: r.captchaToken,
                    });
              if (i) throw i;
              if (!o) throw "An error occurred on sign up.";
              let s = null,
                a = null;
              return (
                o.access_token &&
                  ((s = o),
                  (a = s.user),
                  this._saveSession(s),
                  this._notifyAllSubscribers("SIGNED_IN")),
                o.id && (a = o),
                { user: a, session: s, error: null }
              );
            } catch (n) {
              return { user: null, session: null, error: n };
            }
          });
        }
        signIn(
          {
            email: n,
            phone: e,
            password: t,
            refreshToken: r,
            provider: o,
            oidc: i,
          },
          s = {}
        ) {
          return E(this, void 0, void 0, function* () {
            try {
              if ((this._removeSession(), n && !t)) {
                const { error: e } = yield this.api.sendMagicLinkEmail(n, {
                  redirectTo: s.redirectTo,
                  shouldCreateUser: s.shouldCreateUser,
                  captchaToken: s.captchaToken,
                });
                return { user: null, session: null, error: e };
              }
              if (n && t)
                return this._handleEmailSignIn(n, t, {
                  redirectTo: s.redirectTo,
                  captchaToken: s.captchaToken,
                });
              if (e && !t) {
                const { error: n } = yield this.api.sendMobileOTP(e, {
                  shouldCreateUser: s.shouldCreateUser,
                  captchaToken: s.captchaToken,
                });
                return { user: null, session: null, error: n };
              }
              if (e && t) return this._handlePhoneSignIn(e, t);
              if (r) {
                const { error: n } = yield this._callRefreshToken(r);
                if (n) throw n;
                return {
                  user: this.currentUser,
                  session: this.currentSession,
                  error: null,
                };
              }
              if (o)
                return this._handleProviderSignIn(o, {
                  redirectTo: s.redirectTo,
                  scopes: s.scopes,
                  queryParams: s.queryParams,
                });
              if (i) return this._handleOpenIDConnectSignIn(i);
              throw new Error(
                "You must provide either an email, phone number, a third-party provider or OpenID Connect."
              );
            } catch (n) {
              return { user: null, session: null, error: n };
            }
          });
        }
        verifyOTP(n, e = {}) {
          return E(this, void 0, void 0, function* () {
            try {
              this._removeSession();
              const { data: t, error: r } = yield this.api.verifyOTP(n, e);
              if (r) throw r;
              if (!t) throw "An error occurred on token verification.";
              let o = null,
                i = null;
              return (
                t.access_token &&
                  ((o = t),
                  (i = o.user),
                  this._saveSession(o),
                  this._notifyAllSubscribers("SIGNED_IN")),
                t.id && (i = t),
                { user: i, session: o, error: null }
              );
            } catch (n) {
              return { user: null, session: null, error: n };
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
          var n;
          return E(this, void 0, void 0, function* () {
            try {
              if (
                !(null === (n = this.currentSession) || void 0 === n
                  ? void 0
                  : n.access_token)
              )
                throw new Error("Not logged in.");
              const { error: e } = yield this._callRefreshToken();
              if (e) throw e;
              return {
                data: this.currentSession,
                user: this.currentUser,
                error: null,
              };
            } catch (n) {
              return { data: null, user: null, error: n };
            }
          });
        }
        update(n) {
          var e;
          return E(this, void 0, void 0, function* () {
            try {
              if (
                !(null === (e = this.currentSession) || void 0 === e
                  ? void 0
                  : e.access_token)
              )
                throw new Error("Not logged in.");
              const { user: t, error: r } = yield this.api.updateUser(
                this.currentSession.access_token,
                n
              );
              if (r) throw r;
              if (!t) throw Error("Invalid user data.");
              const o = Object.assign(Object.assign({}, this.currentSession), {
                user: t,
              });
              return (
                this._saveSession(o),
                this._notifyAllSubscribers("USER_UPDATED"),
                { data: t, user: t, error: null }
              );
            } catch (n) {
              return { data: null, user: null, error: n };
            }
          });
        }
        setSession(n) {
          return E(this, void 0, void 0, function* () {
            try {
              if (!n) throw new Error("No current session.");
              const { data: e, error: t } = yield this.api.refreshAccessToken(
                n
              );
              return t
                ? { session: null, error: t }
                : (this._saveSession(e),
                  this._notifyAllSubscribers("SIGNED_IN"),
                  { session: e, error: null });
            } catch (n) {
              return { error: n, session: null };
            }
          });
        }
        setAuth(n) {
          return (
            (this.currentSession = Object.assign(
              Object.assign({}, this.currentSession),
              { access_token: n, token_type: "bearer", user: this.user() }
            )),
            this._notifyAllSubscribers("TOKEN_REFRESHED"),
            this.currentSession
          );
        }
        getSessionFromUrl(n) {
          return E(this, void 0, void 0, function* () {
            try {
              if (!g()) throw new Error("No browser detected.");
              const e = m("error_description");
              if (e) throw new Error(e);
              const t = m("provider_token"),
                r = m("access_token");
              if (!r) throw new Error("No access_token detected.");
              const o = m("expires_in");
              if (!o) throw new Error("No expires_in detected.");
              const i = m("refresh_token");
              if (!i) throw new Error("No refresh_token detected.");
              const s = m("token_type");
              if (!s) throw new Error("No token_type detected.");
              const a = Math.round(Date.now() / 1e3) + parseInt(o),
                { user: A, error: c } = yield this.api.getUser(r);
              if (c) throw c;
              const d = {
                provider_token: t,
                access_token: r,
                expires_in: parseInt(o),
                expires_at: a,
                refresh_token: i,
                token_type: s,
                user: A,
              };
              if (null == n ? void 0 : n.storeSession) {
                this._saveSession(d);
                const n = m("type");
                this._notifyAllSubscribers("SIGNED_IN"),
                  "recovery" === n &&
                    this._notifyAllSubscribers("PASSWORD_RECOVERY");
              }
              return (window.location.hash = ""), { data: d, error: null };
            } catch (n) {
              return { data: null, error: n };
            }
          });
        }
        signOut() {
          var n;
          return E(this, void 0, void 0, function* () {
            const e =
              null === (n = this.currentSession) || void 0 === n
                ? void 0
                : n.access_token;
            if (
              (this._removeSession(),
              this._notifyAllSubscribers("SIGNED_OUT"),
              e)
            ) {
              const { error: n } = yield this.api.signOut(e);
              if (n) return { error: n };
            }
            return { error: null };
          });
        }
        onAuthStateChange(n) {
          try {
            const e = "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(
                /[xy]/g,
                function (n) {
                  const e = (16 * Math.random()) | 0;
                  return ("x" == n ? e : (3 & e) | 8).toString(16);
                }
              ),
              t = {
                id: e,
                callback: n,
                unsubscribe: () => {
                  this.stateChangeEmitters.delete(e);
                },
              };
            return this.stateChangeEmitters.set(e, t), { data: t, error: null };
          } catch (n) {
            return { data: null, error: n };
          }
        }
        _handleEmailSignIn(n, e, t = {}) {
          var r, o;
          return E(this, void 0, void 0, function* () {
            try {
              const { data: i, error: s } = yield this.api.signInWithEmail(
                n,
                e,
                { redirectTo: t.redirectTo, captchaToken: t.captchaToken }
              );
              return s || !i
                ? { data: null, user: null, session: null, error: s }
                : (((null === (r = null == i ? void 0 : i.user) || void 0 === r
                    ? void 0
                    : r.confirmed_at) ||
                    (null === (o = null == i ? void 0 : i.user) || void 0 === o
                      ? void 0
                      : o.email_confirmed_at)) &&
                    (this._saveSession(i),
                    this._notifyAllSubscribers("SIGNED_IN")),
                  { data: i, user: i.user, session: i, error: null });
            } catch (n) {
              return { data: null, user: null, session: null, error: n };
            }
          });
        }
        _handlePhoneSignIn(n, e, t = {}) {
          var r;
          return E(this, void 0, void 0, function* () {
            try {
              const { data: o, error: i } = yield this.api.signInWithPhone(
                n,
                e,
                t
              );
              return i || !o
                ? { data: null, user: null, session: null, error: i }
                : ((null === (r = null == o ? void 0 : o.user) || void 0 === r
                    ? void 0
                    : r.phone_confirmed_at) &&
                    (this._saveSession(o),
                    this._notifyAllSubscribers("SIGNED_IN")),
                  { data: o, user: o.user, session: o, error: null });
            } catch (n) {
              return { data: null, user: null, session: null, error: n };
            }
          });
        }
        _handleProviderSignIn(n, e = {}) {
          const t = this.api.getUrlForProvider(n, {
            redirectTo: e.redirectTo,
            scopes: e.scopes,
            queryParams: e.queryParams,
          });
          try {
            return (
              g() && (window.location.href = t),
              {
                provider: n,
                url: t,
                data: null,
                session: null,
                user: null,
                error: null,
              }
            );
          } catch (e) {
            return t
              ? {
                  provider: n,
                  url: t,
                  data: null,
                  session: null,
                  user: null,
                  error: null,
                }
              : { data: null, user: null, session: null, error: e };
          }
        }
        _handleOpenIDConnectSignIn({
          id_token: n,
          nonce: e,
          client_id: t,
          issuer: r,
          provider: o,
        }) {
          return E(this, void 0, void 0, function* () {
            if (n && e && ((t && r) || o))
              try {
                const { data: i, error: s } =
                  yield this.api.signInWithOpenIDConnect({
                    id_token: n,
                    nonce: e,
                    client_id: t,
                    issuer: r,
                    provider: o,
                  });
                return s || !i
                  ? { user: null, session: null, error: s }
                  : (this._saveSession(i),
                    this._notifyAllSubscribers("SIGNED_IN"),
                    { user: i.user, session: i, error: null });
              } catch (n) {
                return { user: null, session: null, error: n };
              }
            throw new Error(
              "You must provide a OpenID Connect provider with your id token and nonce."
            );
          });
        }
        _recoverSession() {
          try {
            const n = ((n, e) => {
              const t =
                g() && (null == n ? void 0 : n.getItem("supabase.auth.token"));
              if (!t || "string" != typeof t) return null;
              try {
                return JSON.parse(t);
              } catch (n) {
                return t;
              }
            })(this.localStorage);
            if (!n) return null;
            const { currentSession: e, expiresAt: t } = n;
            t >= Math.round(Date.now() / 1e3) + 10 &&
              (null == e ? void 0 : e.user) &&
              (this._saveSession(e), this._notifyAllSubscribers("SIGNED_IN"));
          } catch (n) {
            console.log("error", n);
          }
        }
        _recoverAndRefresh() {
          return E(this, void 0, void 0, function* () {
            try {
              const r = yield ((n = this.localStorage),
              t,
              u(void 0, void 0, void 0, function* () {
                const e =
                  g() &&
                  (yield null == n ? void 0 : n.getItem("supabase.auth.token"));
                if (!e) return null;
                try {
                  return JSON.parse(e);
                } catch (n) {
                  return e;
                }
              }));
              if (!r) return null;
              const { currentSession: o, expiresAt: i } = r;
              if (i < Math.round(Date.now() / 1e3) + 10)
                if (this.autoRefreshToken && o.refresh_token) {
                  this.networkRetries++;
                  const { error: n } = yield this._callRefreshToken(
                    o.refresh_token
                  );
                  if (n) {
                    if (
                      (console.log(n.message),
                      n.message === e && this.networkRetries < 10)
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
                o
                  ? (this._saveSession(o),
                    this._notifyAllSubscribers("SIGNED_IN"))
                  : (console.log("Current session is missing data."),
                    this._removeSession());
            } catch (n) {
              return console.error(n), null;
            }
            var n;
          });
        }
        _callRefreshToken(n) {
          var e;
          return (
            void 0 === n &&
              (n =
                null === (e = this.currentSession) || void 0 === e
                  ? void 0
                  : e.refresh_token),
            E(this, void 0, void 0, function* () {
              try {
                if (!n) throw new Error("No current session.");
                const { data: e, error: t } = yield this.api.refreshAccessToken(
                  n
                );
                if (t) throw t;
                if (!e) throw Error("Invalid session data.");
                return (
                  this._saveSession(e),
                  this._notifyAllSubscribers("TOKEN_REFRESHED"),
                  this._notifyAllSubscribers("SIGNED_IN"),
                  { data: e, error: null }
                );
              } catch (n) {
                return { data: null, error: n };
              }
            })
          );
        }
        _notifyAllSubscribers(n) {
          this.stateChangeEmitters.forEach((e) =>
            e.callback(n, this.currentSession)
          );
        }
        _saveSession(n) {
          (this.currentSession = n), (this.currentUser = n.user);
          const e = n.expires_at;
          if (e) {
            const n = e - Math.round(Date.now() / 1e3),
              t = n > 10 ? 10 : 0.5;
            this._startAutoRefreshToken(1e3 * (n - t));
          }
          this.persistSession &&
            n.expires_at &&
            this._persistSession(this.currentSession);
        }
        _persistSession(n) {
          const e = { currentSession: n, expiresAt: n.expires_at };
          ((n, e, t) => {
            u(void 0, void 0, void 0, function* () {
              g() &&
                (yield null == n
                  ? void 0
                  : n.setItem("supabase.auth.token", JSON.stringify(t)));
            });
          })(this.localStorage, 0, e);
        }
        _removeSession() {
          return E(this, void 0, void 0, function* () {
            var n;
            (this.currentSession = null),
              (this.currentUser = null),
              this.refreshTokenTimer && clearTimeout(this.refreshTokenTimer),
              (n = this.localStorage),
              u(void 0, void 0, void 0, function* () {
                g() &&
                  (yield null == n
                    ? void 0
                    : n.removeItem("supabase.auth.token"));
              });
          });
        }
        _startAutoRefreshToken(n) {
          this.refreshTokenTimer && clearTimeout(this.refreshTokenTimer),
            n <= 0 ||
              !this.autoRefreshToken ||
              ((this.refreshTokenTimer = setTimeout(
                () =>
                  E(this, void 0, void 0, function* () {
                    this.networkRetries++;
                    const { error: n } = yield this._callRefreshToken();
                    n || (this.networkRetries = 0),
                      (null == n ? void 0 : n.message) === e &&
                        this.networkRetries < 10 &&
                        this._startAutoRefreshToken(
                          100 * Math.pow(2, this.networkRetries)
                        );
                  }),
                n
              )),
              "function" == typeof this.refreshTokenTimer.unref &&
                this.refreshTokenTimer.unref());
        }
        _listenForMultiTabEvents() {
          if (
            !this.multiTab ||
            !g() ||
            !(null === window || void 0 === window
              ? void 0
              : window.addEventListener)
          )
            return !1;
          try {
            null === window ||
              void 0 === window ||
              window.addEventListener("storage", (n) => {
                var e;
                if (n.key === t) {
                  const t = JSON.parse(String(n.newValue));
                  (
                    null === (e = null == t ? void 0 : t.currentSession) ||
                    void 0 === e
                      ? void 0
                      : e.access_token
                  )
                    ? (this._saveSession(t.currentSession),
                      this._notifyAllSubscribers("SIGNED_IN"))
                    : (this._removeSession(),
                      this._notifyAllSubscribers("SIGNED_OUT"));
                }
              });
          } catch (n) {
            console.error("_listenForMultiTabEvents", n);
          }
        }
        _handleVisibilityChange() {
          if (
            !this.multiTab ||
            !g() ||
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
          } catch (n) {
            console.error("_handleVisibilityChange", n);
          }
        }
      } {
        constructor(n) {
          super(n);
        }
      }
      var v = function (n, e, t, r) {
        return new (t || (t = Promise))(function (o, i) {
          function s(n) {
            try {
              A(r.next(n));
            } catch (n) {
              i(n);
            }
          }
          function a(n) {
            try {
              A(r.throw(n));
            } catch (n) {
              i(n);
            }
          }
          function A(n) {
            var e;
            n.done
              ? o(n.value)
              : ((e = n.value),
                e instanceof t
                  ? e
                  : new t(function (n) {
                      n(e);
                    })).then(s, a);
          }
          A((r = r.apply(n, e || [])).next());
        });
      };
      class y {
        constructor(n) {
          let e;
          Object.assign(this, n),
            (e = n.fetch
              ? n.fetch
              : "undefined" == typeof fetch
              ? (...n) =>
                  v(this, void 0, void 0, function* () {
                    return yield (yield s
                      .e(98)
                      .then(s.t.bind(s, 98, 23))).fetch(...n);
                  })
              : fetch),
            (this.fetch = (...n) => e(...n)),
            (this.shouldThrowOnError = n.shouldThrowOnError || !1),
            (this.allowEmpty = n.allowEmpty || !1);
        }
        throwOnError(n) {
          return null == n && (n = !0), (this.shouldThrowOnError = n), this;
        }
        then(n, e) {
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
          }).then((n) =>
            v(this, void 0, void 0, function* () {
              var e, t, r, o;
              let i = null,
                s = null,
                a = null,
                A = n.status,
                c = n.statusText;
              if (n.ok) {
                const o =
                  null === (e = this.headers.Prefer) || void 0 === e
                    ? void 0
                    : e.split(",").includes("return=minimal");
                if ("HEAD" !== this.method && !o) {
                  const e = yield n.text();
                  e &&
                    (s =
                      "text/csv" === this.headers.Accept ? e : JSON.parse(e));
                }
                const i =
                    null === (t = this.headers.Prefer) || void 0 === t
                      ? void 0
                      : t.match(/count=(exact|planned|estimated)/),
                  A =
                    null === (r = n.headers.get("content-range")) ||
                    void 0 === r
                      ? void 0
                      : r.split("/");
                i && A && A.length > 1 && (a = parseInt(A[1]));
              } else {
                const e = yield n.text();
                try {
                  i = JSON.parse(e);
                } catch (n) {
                  i = { message: e };
                }
                if (
                  (i &&
                    this.allowEmpty &&
                    (null === (o = null == i ? void 0 : i.details) ||
                    void 0 === o
                      ? void 0
                      : o.includes("Results contain 0 rows")) &&
                    ((i = null), (A = 200), (c = "OK")),
                  i && this.shouldThrowOnError)
                )
                  throw i;
              }
              return {
                error: i,
                data: s,
                count: a,
                status: A,
                statusText: c,
                body: s,
              };
            })
          );
          return (
            this.shouldThrowOnError ||
              (t = t.catch((n) => ({
                error: {
                  message: `FetchError: ${n.message}`,
                  details: "",
                  hint: "",
                  code: n.code || "",
                },
                data: null,
                body: null,
                count: null,
                status: 400,
                statusText: "Bad Request",
              }))),
            t.then(n, e)
          );
        }
      }
      class k extends y {
        select(n = "*") {
          let e = !1;
          const t = n
            .split("")
            .map((n) => (/\s/.test(n) && !e ? "" : ('"' === n && (e = !e), n)))
            .join("");
          return this.url.searchParams.set("select", t), this;
        }
        order(
          n,
          { ascending: e = !0, nullsFirst: t = !1, foreignTable: r } = {}
        ) {
          const o = void 0 === r ? "order" : `${r}.order`,
            i = this.url.searchParams.get(o);
          return (
            this.url.searchParams.set(
              o,
              `${i ? `${i},` : ""}${n}.${e ? "asc" : "desc"}.${
                t ? "nullsfirst" : "nullslast"
              }`
            ),
            this
          );
        }
        limit(n, { foreignTable: e } = {}) {
          const t = void 0 === e ? "limit" : `${e}.limit`;
          return this.url.searchParams.set(t, `${n}`), this;
        }
        range(n, e, { foreignTable: t } = {}) {
          const r = void 0 === t ? "offset" : `${t}.offset`,
            o = void 0 === t ? "limit" : `${t}.limit`;
          return (
            this.url.searchParams.set(r, `${n}`),
            this.url.searchParams.set(o, "" + (e - n + 1)),
            this
          );
        }
        abortSignal(n) {
          return (this.signal = n), this;
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
      class x extends k {
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
        not(n, e, t) {
          return this.url.searchParams.append(`${n}`, `not.${e}.${t}`), this;
        }
        or(n, { foreignTable: e } = {}) {
          const t = void 0 === e ? "or" : `${e}.or`;
          return this.url.searchParams.append(t, `(${n})`), this;
        }
        eq(n, e) {
          return this.url.searchParams.append(`${n}`, `eq.${e}`), this;
        }
        neq(n, e) {
          return this.url.searchParams.append(`${n}`, `neq.${e}`), this;
        }
        gt(n, e) {
          return this.url.searchParams.append(`${n}`, `gt.${e}`), this;
        }
        gte(n, e) {
          return this.url.searchParams.append(`${n}`, `gte.${e}`), this;
        }
        lt(n, e) {
          return this.url.searchParams.append(`${n}`, `lt.${e}`), this;
        }
        lte(n, e) {
          return this.url.searchParams.append(`${n}`, `lte.${e}`), this;
        }
        like(n, e) {
          return this.url.searchParams.append(`${n}`, `like.${e}`), this;
        }
        ilike(n, e) {
          return this.url.searchParams.append(`${n}`, `ilike.${e}`), this;
        }
        is(n, e) {
          return this.url.searchParams.append(`${n}`, `is.${e}`), this;
        }
        in(n, e) {
          const t = e
            .map((n) =>
              "string" == typeof n && new RegExp("[,()]").test(n)
                ? `"${n}"`
                : `${n}`
            )
            .join(",");
          return this.url.searchParams.append(`${n}`, `in.(${t})`), this;
        }
        contains(n, e) {
          return (
            "string" == typeof e
              ? this.url.searchParams.append(`${n}`, `cs.${e}`)
              : Array.isArray(e)
              ? this.url.searchParams.append(`${n}`, `cs.{${e.join(",")}}`)
              : this.url.searchParams.append(`${n}`, `cs.${JSON.stringify(e)}`),
            this
          );
        }
        containedBy(n, e) {
          return (
            "string" == typeof e
              ? this.url.searchParams.append(`${n}`, `cd.${e}`)
              : Array.isArray(e)
              ? this.url.searchParams.append(`${n}`, `cd.{${e.join(",")}}`)
              : this.url.searchParams.append(`${n}`, `cd.${JSON.stringify(e)}`),
            this
          );
        }
        rangeLt(n, e) {
          return this.url.searchParams.append(`${n}`, `sl.${e}`), this;
        }
        rangeGt(n, e) {
          return this.url.searchParams.append(`${n}`, `sr.${e}`), this;
        }
        rangeGte(n, e) {
          return this.url.searchParams.append(`${n}`, `nxl.${e}`), this;
        }
        rangeLte(n, e) {
          return this.url.searchParams.append(`${n}`, `nxr.${e}`), this;
        }
        rangeAdjacent(n, e) {
          return this.url.searchParams.append(`${n}`, `adj.${e}`), this;
        }
        overlaps(n, e) {
          return (
            "string" == typeof e
              ? this.url.searchParams.append(`${n}`, `ov.${e}`)
              : this.url.searchParams.append(`${n}`, `ov.{${e.join(",")}}`),
            this
          );
        }
        textSearch(n, e, { config: t, type: r = null } = {}) {
          let o = "";
          "plain" === r
            ? (o = "pl")
            : "phrase" === r
            ? (o = "ph")
            : "websearch" === r && (o = "w");
          const i = void 0 === t ? "" : `(${t})`;
          return this.url.searchParams.append(`${n}`, `${o}fts${i}.${e}`), this;
        }
        fts(n, e, { config: t } = {}) {
          const r = void 0 === t ? "" : `(${t})`;
          return this.url.searchParams.append(`${n}`, `fts${r}.${e}`), this;
        }
        plfts(n, e, { config: t } = {}) {
          const r = void 0 === t ? "" : `(${t})`;
          return this.url.searchParams.append(`${n}`, `plfts${r}.${e}`), this;
        }
        phfts(n, e, { config: t } = {}) {
          const r = void 0 === t ? "" : `(${t})`;
          return this.url.searchParams.append(`${n}`, `phfts${r}.${e}`), this;
        }
        wfts(n, e, { config: t } = {}) {
          const r = void 0 === t ? "" : `(${t})`;
          return this.url.searchParams.append(`${n}`, `wfts${r}.${e}`), this;
        }
        filter(n, e, t) {
          return this.url.searchParams.append(`${n}`, `${e}.${t}`), this;
        }
        match(n) {
          return (
            Object.keys(n).forEach((e) => {
              this.url.searchParams.append(`${e}`, `eq.${n[e]}`);
            }),
            this
          );
        }
      }
      class _ extends y {
        constructor(
          n,
          { headers: e = {}, schema: t, fetch: r, shouldThrowOnError: o } = {}
        ) {
          super({ fetch: r, shouldThrowOnError: o }),
            (this.url = new URL(n)),
            (this.headers = Object.assign({}, e)),
            (this.schema = t);
        }
        select(n = "*", { head: e = !1, count: t = null } = {}) {
          this.method = "GET";
          let r = !1;
          const o = n
            .split("")
            .map((n) => (/\s/.test(n) && !r ? "" : ('"' === n && (r = !r), n)))
            .join("");
          return (
            this.url.searchParams.set("select", o),
            t && (this.headers.Prefer = `count=${t}`),
            e && (this.method = "HEAD"),
            new x(this)
          );
        }
        insert(
          n,
          {
            upsert: e = !1,
            onConflict: t,
            returning: r = "representation",
            count: o = null,
          } = {}
        ) {
          this.method = "POST";
          const i = [`return=${r}`];
          if (
            (e && i.push("resolution=merge-duplicates"),
            e && void 0 !== t && this.url.searchParams.set("on_conflict", t),
            (this.body = n),
            o && i.push(`count=${o}`),
            this.headers.Prefer && i.unshift(this.headers.Prefer),
            (this.headers.Prefer = i.join(",")),
            Array.isArray(n))
          ) {
            const e = n.reduce((n, e) => n.concat(Object.keys(e)), []);
            if (e.length > 0) {
              const n = [...new Set(e)].map((n) => `"${n}"`);
              this.url.searchParams.set("columns", n.join(","));
            }
          }
          return new x(this);
        }
        upsert(
          n,
          {
            onConflict: e,
            returning: t = "representation",
            count: r = null,
            ignoreDuplicates: o = !1,
          } = {}
        ) {
          this.method = "POST";
          const i = [
            `resolution=${o ? "ignore" : "merge"}-duplicates`,
            `return=${t}`,
          ];
          return (
            void 0 !== e && this.url.searchParams.set("on_conflict", e),
            (this.body = n),
            r && i.push(`count=${r}`),
            this.headers.Prefer && i.unshift(this.headers.Prefer),
            (this.headers.Prefer = i.join(",")),
            new x(this)
          );
        }
        update(n, { returning: e = "representation", count: t = null } = {}) {
          this.method = "PATCH";
          const r = [`return=${e}`];
          return (
            (this.body = n),
            t && r.push(`count=${t}`),
            this.headers.Prefer && r.unshift(this.headers.Prefer),
            (this.headers.Prefer = r.join(",")),
            new x(this)
          );
        }
        delete({ returning: n = "representation", count: e = null } = {}) {
          this.method = "DELETE";
          const t = [`return=${n}`];
          return (
            e && t.push(`count=${e}`),
            this.headers.Prefer && t.unshift(this.headers.Prefer),
            (this.headers.Prefer = t.join(",")),
            new x(this)
          );
        }
      }
      class S extends y {
        constructor(
          n,
          { headers: e = {}, schema: t, fetch: r, shouldThrowOnError: o } = {}
        ) {
          super({ fetch: r, shouldThrowOnError: o }),
            (this.url = new URL(n)),
            (this.headers = Object.assign({}, e)),
            (this.schema = t);
        }
        rpc(n, { head: e = !1, count: t = null } = {}) {
          return (
            e
              ? ((this.method = "HEAD"),
                n &&
                  Object.entries(n).forEach(([n, e]) => {
                    this.url.searchParams.append(n, e);
                  }))
              : ((this.method = "POST"), (this.body = n)),
            t &&
              (void 0 !== this.headers.Prefer
                ? (this.headers.Prefer += `,count=${t}`)
                : (this.headers.Prefer = `count=${t}`)),
            new x(this)
          );
        }
      }
      const T = { "X-Client-Info": "postgrest-js/0.37.4" };
      class j {
        constructor(
          n,
          { headers: e = {}, schema: t, fetch: r, throwOnError: o } = {}
        ) {
          (this.url = n),
            (this.headers = Object.assign(Object.assign({}, T), e)),
            (this.schema = t),
            (this.fetch = r),
            (this.shouldThrowOnError = o);
        }
        auth(n) {
          return (this.headers.Authorization = `Bearer ${n}`), this;
        }
        from(n) {
          const e = `${this.url}/${n}`;
          return new _(e, {
            headers: this.headers,
            schema: this.schema,
            fetch: this.fetch,
            shouldThrowOnError: this.shouldThrowOnError,
          });
        }
        rpc(n, e, { head: t = !1, count: r = null } = {}) {
          const o = `${this.url}/rpc/${n}`;
          return new S(o, {
            headers: this.headers,
            schema: this.schema,
            fetch: this.fetch,
            shouldThrowOnError: this.shouldThrowOnError,
          }).rpc(e, { head: t, count: r });
        }
      }
      var O;
      !(function (n) {
        (n.abstime = "abstime"),
          (n.bool = "bool"),
          (n.date = "date"),
          (n.daterange = "daterange"),
          (n.float4 = "float4"),
          (n.float8 = "float8"),
          (n.int2 = "int2"),
          (n.int4 = "int4"),
          (n.int4range = "int4range"),
          (n.int8 = "int8"),
          (n.int8range = "int8range"),
          (n.json = "json"),
          (n.jsonb = "jsonb"),
          (n.money = "money"),
          (n.numeric = "numeric"),
          (n.oid = "oid"),
          (n.reltime = "reltime"),
          (n.text = "text"),
          (n.time = "time"),
          (n.timestamp = "timestamp"),
          (n.timestamptz = "timestamptz"),
          (n.timetz = "timetz"),
          (n.tsrange = "tsrange"),
          (n.tstzrange = "tstzrange");
      })(O || (O = {}));
      const $ = (n, e, t = {}) => {
          var r;
          const o = null !== (r = t.skipTypes) && void 0 !== r ? r : [];
          return Object.keys(e).reduce(
            (t, r) => ((t[r] = I(r, n, e, o)), t),
            {}
          );
        },
        I = (n, e, t, r) => {
          const o = e.find((e) => e.name === n),
            i = null == o ? void 0 : o.type,
            s = t[n];
          return i && !r.includes(i) ? D(i, s) : R(s);
        },
        D = (n, e) => {
          if ("_" === n.charAt(0)) {
            const t = n.slice(1, n.length);
            return M(e, t);
          }
          switch (n) {
            case O.bool:
              return P(e);
            case O.float4:
            case O.float8:
            case O.int2:
            case O.int4:
            case O.int8:
            case O.numeric:
            case O.oid:
              return z(e);
            case O.json:
            case O.jsonb:
              return U(e);
            case O.timestamp:
              return N(e);
            case O.abstime:
            case O.date:
            case O.daterange:
            case O.int4range:
            case O.int8range:
            case O.money:
            case O.reltime:
            case O.text:
            case O.time:
            case O.timestamptz:
            case O.timetz:
            case O.tsrange:
            case O.tstzrange:
            default:
              return R(e);
          }
        },
        R = (n) => n,
        P = (n) => {
          switch (n) {
            case "t":
              return !0;
            case "f":
              return !1;
            default:
              return n;
          }
        },
        z = (n) => {
          if ("string" == typeof n) {
            const e = parseFloat(n);
            if (!Number.isNaN(e)) return e;
          }
          return n;
        },
        U = (n) => {
          if ("string" == typeof n)
            try {
              return JSON.parse(n);
            } catch (e) {
              return console.log(`JSON parse error: ${e}`), n;
            }
          return n;
        },
        M = (n, e) => {
          if ("string" != typeof n) return n;
          const t = n.length - 1,
            r = n[t];
          if ("{" === n[0] && "}" === r) {
            let r;
            const o = n.slice(1, t);
            try {
              r = JSON.parse("[" + o + "]");
            } catch (n) {
              r = o ? o.split(",") : [];
            }
            return r.map((n) => D(e, n));
          }
          return n;
        },
        N = (n) => ("string" == typeof n ? n.replace(" ", "T") : n);
      var q = s(840);
      const G = { "X-Client-Info": "realtime-js/1.7.4" };
      var F, L, J, H, W;
      !(function (n) {
        (n[(n.connecting = 0)] = "connecting"),
          (n[(n.open = 1)] = "open"),
          (n[(n.closing = 2)] = "closing"),
          (n[(n.closed = 3)] = "closed");
      })(F || (F = {})),
        (function (n) {
          (n.closed = "closed"),
            (n.errored = "errored"),
            (n.joined = "joined"),
            (n.joining = "joining"),
            (n.leaving = "leaving");
        })(L || (L = {})),
        (function (n) {
          (n.close = "phx_close"),
            (n.error = "phx_error"),
            (n.join = "phx_join"),
            (n.reply = "phx_reply"),
            (n.leave = "phx_leave"),
            (n.access_token = "access_token");
        })(J || (J = {})),
        (function (n) {
          n.websocket = "websocket";
        })(H || (H = {})),
        (function (n) {
          (n.Connecting = "connecting"),
            (n.Open = "open"),
            (n.Closing = "closing"),
            (n.Closed = "closed");
        })(W || (W = {}));
      class K {
        constructor(n, e) {
          (this.callback = n),
            (this.timerCalc = e),
            (this.timer = void 0),
            (this.tries = 0),
            (this.callback = n),
            (this.timerCalc = e);
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
      class Y {
        constructor() {
          this.HEADER_LENGTH = 1;
        }
        decode(n, e) {
          return n.constructor === ArrayBuffer
            ? e(this._binaryDecode(n))
            : e("string" == typeof n ? JSON.parse(n) : {});
        }
        _binaryDecode(n) {
          const e = new DataView(n),
            t = new TextDecoder();
          return this._decodeBroadcast(n, e, t);
        }
        _decodeBroadcast(n, e, t) {
          const r = e.getUint8(1),
            o = e.getUint8(2);
          let i = this.HEADER_LENGTH + 2;
          const s = t.decode(n.slice(i, i + r));
          i += r;
          const a = t.decode(n.slice(i, i + o));
          return (
            (i += o),
            {
              ref: null,
              topic: s,
              event: a,
              payload: JSON.parse(t.decode(n.slice(i, n.byteLength))),
            }
          );
        }
      }
      class Z {
        constructor(n, e, t = {}, r = 1e4) {
          (this.channel = n),
            (this.event = e),
            (this.payload = t),
            (this.timeout = r),
            (this.sent = !1),
            (this.timeoutTimer = void 0),
            (this.ref = ""),
            (this.receivedResp = null),
            (this.recHooks = []),
            (this.refEvent = null);
        }
        resend(n) {
          (this.timeout = n),
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
        updatePayload(n) {
          this.payload = Object.assign(Object.assign({}, this.payload), n);
        }
        receive(n, e) {
          var t;
          return (
            this._hasReceived(n) &&
              e(
                null === (t = this.receivedResp) || void 0 === t
                  ? void 0
                  : t.response
              ),
            this.recHooks.push({ status: n, callback: e }),
            this
          );
        }
        startTimeout() {
          this.timeoutTimer ||
            ((this.ref = this.channel.socket.makeRef()),
            (this.refEvent = this.channel.replyEventName(this.ref)),
            this.channel.on(this.refEvent, (n) => {
              this._cancelRefEvent(),
                this._cancelTimeout(),
                (this.receivedResp = n),
                this._matchReceive(n);
            }),
            (this.timeoutTimer = setTimeout(() => {
              this.trigger("timeout", {});
            }, this.timeout)));
        }
        trigger(n, e) {
          this.refEvent &&
            this.channel.trigger(this.refEvent, { status: n, response: e });
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
        _matchReceive({ status: n, response: e }) {
          this.recHooks
            .filter((e) => e.status === n)
            .forEach((n) => n.callback(e));
        }
        _hasReceived(n) {
          return this.receivedResp && this.receivedResp.status === n;
        }
      }
      class V {
        constructor(n, e = {}, t) {
          (this.topic = n),
            (this.params = e),
            (this.socket = t),
            (this.bindings = []),
            (this.state = L.closed),
            (this.joinedOnce = !1),
            (this.pushBuffer = []),
            (this.timeout = this.socket.timeout),
            (this.joinPush = new Z(this, J.join, this.params, this.timeout)),
            (this.rejoinTimer = new K(
              () => this.rejoinUntilConnected(),
              this.socket.reconnectAfterMs
            )),
            this.joinPush.receive("ok", () => {
              (this.state = L.joined),
                this.rejoinTimer.reset(),
                this.pushBuffer.forEach((n) => n.send()),
                (this.pushBuffer = []);
            }),
            this.onClose(() => {
              this.rejoinTimer.reset(),
                this.socket.log(
                  "channel",
                  `close ${this.topic} ${this.joinRef()}`
                ),
                (this.state = L.closed),
                this.socket.remove(this);
            }),
            this.onError((n) => {
              this.isLeaving() ||
                this.isClosed() ||
                (this.socket.log("channel", `error ${this.topic}`, n),
                (this.state = L.errored),
                this.rejoinTimer.scheduleTimeout());
            }),
            this.joinPush.receive("timeout", () => {
              this.isJoining() &&
                (this.socket.log(
                  "channel",
                  `timeout ${this.topic}`,
                  this.joinPush.timeout
                ),
                (this.state = L.errored),
                this.rejoinTimer.scheduleTimeout());
            }),
            this.on(J.reply, (n, e) => {
              this.trigger(this.replyEventName(e), n);
            });
        }
        rejoinUntilConnected() {
          this.rejoinTimer.scheduleTimeout(),
            this.socket.isConnected() && this.rejoin();
        }
        subscribe(n = this.timeout) {
          if (this.joinedOnce)
            throw "tried to subscribe multiple times. 'subscribe' can only be called a single time per channel instance";
          return (this.joinedOnce = !0), this.rejoin(n), this.joinPush;
        }
        onClose(n) {
          this.on(J.close, n);
        }
        onError(n) {
          this.on(J.error, (e) => n(e));
        }
        on(n, e) {
          this.bindings.push({ event: n, callback: e });
        }
        off(n) {
          this.bindings = this.bindings.filter((e) => e.event !== n);
        }
        canPush() {
          return this.socket.isConnected() && this.isJoined();
        }
        push(n, e, t = this.timeout) {
          if (!this.joinedOnce)
            throw `tried to push '${n}' to '${this.topic}' before joining. Use channel.subscribe() before pushing events`;
          let r = new Z(this, n, e, t);
          return (
            this.canPush()
              ? r.send()
              : (r.startTimeout(), this.pushBuffer.push(r)),
            r
          );
        }
        updateJoinPayload(n) {
          this.joinPush.updatePayload(n);
        }
        unsubscribe(n = this.timeout) {
          this.state = L.leaving;
          let e = () => {
            this.socket.log("channel", `leave ${this.topic}`),
              this.trigger(J.close, "leave", this.joinRef());
          };
          this.joinPush.destroy();
          let t = new Z(this, J.leave, {}, n);
          return (
            t.receive("ok", () => e()).receive("timeout", () => e()),
            t.send(),
            this.canPush() || t.trigger("ok", {}),
            t
          );
        }
        onMessage(n, e, t) {
          return e;
        }
        isMember(n) {
          return this.topic === n;
        }
        joinRef() {
          return this.joinPush.ref;
        }
        rejoin(n = this.timeout) {
          this.isLeaving() ||
            (this.socket.leaveOpenTopic(this.topic),
            (this.state = L.joining),
            this.joinPush.resend(n));
        }
        trigger(n, e, t) {
          let { close: r, error: o, leave: i, join: s } = J;
          if (t && [r, o, i, s].indexOf(n) >= 0 && t !== this.joinRef()) return;
          let a = this.onMessage(n, e, t);
          if (e && !a)
            throw "channel onMessage callbacks must return the payload, modified or unmodified";
          this.bindings
            .filter((t) =>
              "*" === t.event
                ? n === (null == e ? void 0 : e.type)
                : t.event === n
            )
            .map((n) => n.callback(a, t));
        }
        replyEventName(n) {
          return `chan_reply_${n}`;
        }
        isClosed() {
          return this.state === L.closed;
        }
        isErrored() {
          return this.state === L.errored;
        }
        isJoined() {
          return this.state === L.joined;
        }
        isJoining() {
          return this.state === L.joining;
        }
        isLeaving() {
          return this.state === L.leaving;
        }
      }
      const X = () => {};
      class Q {
        constructor(n, e) {
          (this.accessToken = null),
            (this.channels = []),
            (this.endPoint = ""),
            (this.headers = G),
            (this.params = {}),
            (this.timeout = 1e4),
            (this.transport = q.w3cwebsocket),
            (this.heartbeatIntervalMs = 3e4),
            (this.longpollerTimeout = 2e4),
            (this.heartbeatTimer = void 0),
            (this.pendingHeartbeatRef = null),
            (this.ref = 0),
            (this.logger = X),
            (this.conn = null),
            (this.sendBuffer = []),
            (this.serializer = new Y()),
            (this.stateChangeCallbacks = {
              open: [],
              close: [],
              error: [],
              message: [],
            }),
            (this.endPoint = `${n}/${H.websocket}`),
            (null == e ? void 0 : e.params) && (this.params = e.params),
            (null == e ? void 0 : e.headers) &&
              (this.headers = Object.assign(
                Object.assign({}, this.headers),
                e.headers
              )),
            (null == e ? void 0 : e.timeout) && (this.timeout = e.timeout),
            (null == e ? void 0 : e.logger) && (this.logger = e.logger),
            (null == e ? void 0 : e.transport) &&
              (this.transport = e.transport),
            (null == e ? void 0 : e.heartbeatIntervalMs) &&
              (this.heartbeatIntervalMs = e.heartbeatIntervalMs),
            (null == e ? void 0 : e.longpollerTimeout) &&
              (this.longpollerTimeout = e.longpollerTimeout),
            (this.reconnectAfterMs = (null == e ? void 0 : e.reconnectAfterMs)
              ? e.reconnectAfterMs
              : (n) => [1e3, 2e3, 5e3, 1e4][n - 1] || 1e4),
            (this.encode = (null == e ? void 0 : e.encode)
              ? e.encode
              : (n, e) => e(JSON.stringify(n))),
            (this.decode = (null == e ? void 0 : e.decode)
              ? e.decode
              : this.serializer.decode.bind(this.serializer)),
            (this.reconnectTimer = new K(() => {
              return (
                (n = this),
                (e = void 0),
                (r = function* () {
                  yield this.disconnect(), this.connect();
                }),
                new ((t = void 0) || (t = Promise))(function (o, i) {
                  function s(n) {
                    try {
                      A(r.next(n));
                    } catch (n) {
                      i(n);
                    }
                  }
                  function a(n) {
                    try {
                      A(r.throw(n));
                    } catch (n) {
                      i(n);
                    }
                  }
                  function A(n) {
                    var e;
                    n.done
                      ? o(n.value)
                      : ((e = n.value),
                        e instanceof t
                          ? e
                          : new t(function (n) {
                              n(e);
                            })).then(s, a);
                  }
                  A((r = r.apply(n, e || [])).next());
                })
              );
              var n, e, t, r;
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
              (this.conn.onerror = (n) => this._onConnError(n)),
              (this.conn.onmessage = (n) => this.onConnMessage(n)),
              (this.conn.onclose = (n) => this._onConnClose(n))));
        }
        disconnect(n, e) {
          return new Promise((t, r) => {
            try {
              this.conn &&
                ((this.conn.onclose = function () {}),
                n ? this.conn.close(n, e || "") : this.conn.close(),
                (this.conn = null),
                this.heartbeatTimer && clearInterval(this.heartbeatTimer),
                this.reconnectTimer.reset()),
                t({ error: null, data: !0 });
            } catch (n) {
              t({ error: n, data: !1 });
            }
          });
        }
        log(n, e, t) {
          this.logger(n, e, t);
        }
        onOpen(n) {
          this.stateChangeCallbacks.open.push(n);
        }
        onClose(n) {
          this.stateChangeCallbacks.close.push(n);
        }
        onError(n) {
          this.stateChangeCallbacks.error.push(n);
        }
        onMessage(n) {
          this.stateChangeCallbacks.message.push(n);
        }
        connectionState() {
          switch (this.conn && this.conn.readyState) {
            case F.connecting:
              return W.Connecting;
            case F.open:
              return W.Open;
            case F.closing:
              return W.Closing;
            default:
              return W.Closed;
          }
        }
        isConnected() {
          return this.connectionState() === W.Open;
        }
        remove(n) {
          this.channels = this.channels.filter(
            (e) => e.joinRef() !== n.joinRef()
          );
        }
        channel(n, e = {}) {
          const t = new V(n, e, this);
          return this.channels.push(t), t;
        }
        push(n) {
          const { topic: e, event: t, payload: r, ref: o } = n;
          let i = () => {
            this.encode(n, (n) => {
              var e;
              null === (e = this.conn) || void 0 === e || e.send(n);
            });
          };
          this.log("push", `${e} ${t} (${o})`, r),
            this.isConnected() ? i() : this.sendBuffer.push(i);
        }
        onConnMessage(n) {
          this.decode(n.data, (n) => {
            let { topic: e, event: t, payload: r, ref: o } = n;
            ((o && o === this.pendingHeartbeatRef) ||
              t === (null == r ? void 0 : r.type)) &&
              (this.pendingHeartbeatRef = null),
              this.log(
                "receive",
                `${r.status || ""} ${e} ${t} ${(o && "(" + o + ")") || ""}`,
                r
              ),
              this.channels
                .filter((n) => n.isMember(e))
                .forEach((n) => n.trigger(t, r, o)),
              this.stateChangeCallbacks.message.forEach((e) => e(n));
          });
        }
        endPointURL() {
          return this._appendParams(
            this.endPoint,
            Object.assign({}, this.params, { vsn: "1.0.0" })
          );
        }
        makeRef() {
          let n = this.ref + 1;
          return (
            n === this.ref ? (this.ref = 0) : (this.ref = n),
            this.ref.toString()
          );
        }
        setAuth(n) {
          (this.accessToken = n),
            this.channels.forEach((e) => {
              n && e.updateJoinPayload({ user_token: n }),
                e.joinedOnce &&
                  e.isJoined() &&
                  e.push(J.access_token, { access_token: n });
            });
        }
        leaveOpenTopic(n) {
          let e = this.channels.find(
            (e) => e.topic === n && (e.isJoined() || e.isJoining())
          );
          e &&
            (this.log("transport", `leaving duplicate topic "${n}"`),
            e.unsubscribe());
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
            this.stateChangeCallbacks.open.forEach((n) => n());
        }
        _onConnClose(n) {
          this.log("transport", "close", n),
            this._triggerChanError(),
            this.heartbeatTimer && clearInterval(this.heartbeatTimer),
            this.reconnectTimer.scheduleTimeout(),
            this.stateChangeCallbacks.close.forEach((e) => e(n));
        }
        _onConnError(n) {
          this.log("transport", n.message),
            this._triggerChanError(),
            this.stateChangeCallbacks.error.forEach((e) => e(n));
        }
        _triggerChanError() {
          this.channels.forEach((n) => n.trigger(J.error));
        }
        _appendParams(n, e) {
          if (0 === Object.keys(e).length) return n;
          const t = n.match(/\?/) ? "&" : "?";
          return `${n}${t}${new URLSearchParams(e)}`;
        }
        _flushSendBuffer() {
          this.isConnected() &&
            this.sendBuffer.length > 0 &&
            (this.sendBuffer.forEach((n) => n()), (this.sendBuffer = []));
        }
        _sendHeartbeat() {
          var n;
          if (this.isConnected()) {
            if (this.pendingHeartbeatRef)
              return (
                (this.pendingHeartbeatRef = null),
                this.log(
                  "transport",
                  "heartbeat timeout. Attempting to re-establish connection"
                ),
                void (
                  null === (n = this.conn) ||
                  void 0 === n ||
                  n.close(1e3, "hearbeat timeout")
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
      class nn {
        constructor(n, e, t, r) {
          const o = {},
            i = "*" === r ? `realtime:${t}` : `realtime:${t}:${r}`,
            s = e.Authorization.split(" ")[1];
          s && (o.user_token = s), (this.subscription = n.channel(i, o));
        }
        getPayloadRecords(n) {
          const e = { new: {}, old: {} };
          return (
            ("INSERT" !== n.type && "UPDATE" !== n.type) ||
              (e.new = $(n.columns, n.record)),
            ("UPDATE" !== n.type && "DELETE" !== n.type) ||
              (e.old = $(n.columns, n.old_record)),
            e
          );
        }
        on(n, e) {
          return (
            this.subscription.on(n, (n) => {
              let t = {
                schema: n.schema,
                table: n.table,
                commit_timestamp: n.commit_timestamp,
                eventType: n.type,
                new: {},
                old: {},
                errors: n.errors,
              };
              (t = Object.assign(
                Object.assign({}, t),
                this.getPayloadRecords(n)
              )),
                e(t);
            }),
            this
          );
        }
        subscribe(n = () => {}) {
          return (
            this.subscription.onError((e) => n("SUBSCRIPTION_ERROR", e)),
            this.subscription.onClose(() => n("CLOSED")),
            this.subscription
              .subscribe()
              .receive("ok", () => n("SUBSCRIBED"))
              .receive("error", (e) => n("SUBSCRIPTION_ERROR", e))
              .receive("timeout", () => n("RETRYING_AFTER_TIMEOUT")),
            this.subscription
          );
        }
      }
      class en extends _ {
        constructor(
          n,
          {
            headers: e = {},
            schema: t,
            realtime: r,
            table: o,
            fetch: i,
            shouldThrowOnError: s,
          }
        ) {
          super(n, { headers: e, schema: t, fetch: i, shouldThrowOnError: s }),
            (this._subscription = null),
            (this._realtime = r),
            (this._headers = e),
            (this._schema = t),
            (this._table = o);
        }
        on(n, e) {
          return (
            this._realtime.isConnected() || this._realtime.connect(),
            this._subscription ||
              (this._subscription = new nn(
                this._realtime,
                this._headers,
                this._schema,
                this._table
              )),
            this._subscription.on(n, e)
          );
        }
      }
      const tn = { "X-Client-Info": "storage-js/1.7.3" };
      var rn = function (n, e, t, r) {
        return new (t || (t = Promise))(function (o, i) {
          function s(n) {
            try {
              A(r.next(n));
            } catch (n) {
              i(n);
            }
          }
          function a(n) {
            try {
              A(r.throw(n));
            } catch (n) {
              i(n);
            }
          }
          function A(n) {
            var e;
            n.done
              ? o(n.value)
              : ((e = n.value),
                e instanceof t
                  ? e
                  : new t(function (n) {
                      n(e);
                    })).then(s, a);
          }
          A((r = r.apply(n, e || [])).next());
        });
      };
      const on = (n) =>
        n.msg ||
        n.message ||
        n.error_description ||
        n.error ||
        JSON.stringify(n);
      function sn(n, e, t, r, o, i) {
        return rn(this, void 0, void 0, function* () {
          return new Promise((s, a) => {
            n(
              t,
              ((n, e, t, r) => {
                const o = {
                  method: n,
                  headers: (null == e ? void 0 : e.headers) || {},
                };
                return "GET" === n
                  ? o
                  : ((o.headers = Object.assign(
                      { "Content-Type": "application/json" },
                      null == e ? void 0 : e.headers
                    )),
                    (o.body = JSON.stringify(r)),
                    Object.assign(Object.assign({}, o), t));
              })(e, r, o, i)
            )
              .then((n) => {
                if (!n.ok) throw n;
                return (null == r ? void 0 : r.noResolveJson) ? s(n) : n.json();
              })
              .then((n) => s(n))
              .catch((n) =>
                ((n, e) => {
                  if ("function" != typeof n.json) return e(n);
                  n.json().then((t) =>
                    e({
                      message: on(t),
                      status: (null == n ? void 0 : n.status) || 500,
                    })
                  );
                })(n, a)
              );
          });
        });
      }
      function an(n, e, t, r) {
        return rn(this, void 0, void 0, function* () {
          return sn(n, "GET", e, t, r);
        });
      }
      function An(n, e, t, r, o) {
        return rn(this, void 0, void 0, function* () {
          return sn(n, "POST", e, r, o, t);
        });
      }
      function cn(n, e, t, r, o) {
        return rn(this, void 0, void 0, function* () {
          return sn(n, "DELETE", e, r, o, t);
        });
      }
      const dn = (n) => {
        let e;
        return (
          (e =
            n ||
            ("undefined" == typeof fetch
              ? (...n) => {
                  return (
                    (e = void 0),
                    (t = void 0),
                    (o = function* () {
                      return yield (yield s
                        .e(98)
                        .then(s.t.bind(s, 98, 23))).fetch(...n);
                    }),
                    new ((r = void 0) || (r = Promise))(function (n, i) {
                      function s(n) {
                        try {
                          A(o.next(n));
                        } catch (n) {
                          i(n);
                        }
                      }
                      function a(n) {
                        try {
                          A(o.throw(n));
                        } catch (n) {
                          i(n);
                        }
                      }
                      function A(e) {
                        var t;
                        e.done
                          ? n(e.value)
                          : ((t = e.value),
                            t instanceof r
                              ? t
                              : new r(function (n) {
                                  n(t);
                                })).then(s, a);
                      }
                      A((o = o.apply(e, t || [])).next());
                    })
                  );
                  var e, t, r, o;
                }
              : fetch)),
          (...n) => e(...n)
        );
      };
      var ln = function (n, e, t, r) {
          return new (t || (t = Promise))(function (o, i) {
            function s(n) {
              try {
                A(r.next(n));
              } catch (n) {
                i(n);
              }
            }
            function a(n) {
              try {
                A(r.throw(n));
              } catch (n) {
                i(n);
              }
            }
            function A(n) {
              var e;
              n.done
                ? o(n.value)
                : ((e = n.value),
                  e instanceof t
                    ? e
                    : new t(function (n) {
                        n(e);
                      })).then(s, a);
            }
            A((r = r.apply(n, e || [])).next());
          });
        },
        hn = function (n, e, t, r) {
          return new (t || (t = Promise))(function (o, i) {
            function s(n) {
              try {
                A(r.next(n));
              } catch (n) {
                i(n);
              }
            }
            function a(n) {
              try {
                A(r.throw(n));
              } catch (n) {
                i(n);
              }
            }
            function A(n) {
              var e;
              n.done
                ? o(n.value)
                : ((e = n.value),
                  e instanceof t
                    ? e
                    : new t(function (n) {
                        n(e);
                      })).then(s, a);
            }
            A((r = r.apply(n, e || [])).next());
          });
        };
      const un = {
          limit: 100,
          offset: 0,
          sortBy: { column: "name", order: "asc" },
        },
        pn = {
          cacheControl: "3600",
          contentType: "text/plain;charset=UTF-8",
          upsert: !1,
        };
      class gn {
        constructor(n, e = {}, t, r) {
          (this.url = n),
            (this.headers = e),
            (this.bucketId = t),
            (this.fetch = dn(r));
        }
        uploadOrUpdate(n, e, t, r) {
          return hn(this, void 0, void 0, function* () {
            try {
              let o;
              const i = Object.assign(Object.assign({}, pn), r),
                s = Object.assign(
                  Object.assign({}, this.headers),
                  "POST" === n && { "x-upsert": String(i.upsert) }
                );
              "undefined" != typeof Blob && t instanceof Blob
                ? ((o = new FormData()),
                  o.append("cacheControl", i.cacheControl),
                  o.append("", t))
                : "undefined" != typeof FormData && t instanceof FormData
                ? ((o = t), o.append("cacheControl", i.cacheControl))
                : ((o = t),
                  (s["cache-control"] = `max-age=${i.cacheControl}`),
                  (s["content-type"] = i.contentType));
              const a = this._removeEmptyFolders(e),
                A = this._getFinalPath(a),
                c = yield this.fetch(`${this.url}/object/${A}`, {
                  method: n,
                  body: o,
                  headers: s,
                });
              return c.ok
                ? { data: { Key: A }, error: null }
                : { data: null, error: yield c.json() };
            } catch (n) {
              return { data: null, error: n };
            }
          });
        }
        upload(n, e, t) {
          return hn(this, void 0, void 0, function* () {
            return this.uploadOrUpdate("POST", n, e, t);
          });
        }
        update(n, e, t) {
          return hn(this, void 0, void 0, function* () {
            return this.uploadOrUpdate("PUT", n, e, t);
          });
        }
        move(n, e) {
          return hn(this, void 0, void 0, function* () {
            try {
              return {
                data: yield An(
                  this.fetch,
                  `${this.url}/object/move`,
                  { bucketId: this.bucketId, sourceKey: n, destinationKey: e },
                  { headers: this.headers }
                ),
                error: null,
              };
            } catch (n) {
              return { data: null, error: n };
            }
          });
        }
        copy(n, e) {
          return hn(this, void 0, void 0, function* () {
            try {
              return {
                data: yield An(
                  this.fetch,
                  `${this.url}/object/copy`,
                  { bucketId: this.bucketId, sourceKey: n, destinationKey: e },
                  { headers: this.headers }
                ),
                error: null,
              };
            } catch (n) {
              return { data: null, error: n };
            }
          });
        }
        createSignedUrl(n, e) {
          return hn(this, void 0, void 0, function* () {
            try {
              const t = this._getFinalPath(n);
              let r = yield An(
                this.fetch,
                `${this.url}/object/sign/${t}`,
                { expiresIn: e },
                { headers: this.headers }
              );
              const o = `${this.url}${r.signedURL}`;
              return (
                (r = { signedURL: o }), { data: r, error: null, signedURL: o }
              );
            } catch (n) {
              return { data: null, error: n, signedURL: null };
            }
          });
        }
        createSignedUrls(n, e) {
          return hn(this, void 0, void 0, function* () {
            try {
              return {
                data: (yield An(
                  this.fetch,
                  `${this.url}/object/sign/${this.bucketId}`,
                  { expiresIn: e, paths: n },
                  { headers: this.headers }
                )).map((n) =>
                  Object.assign(Object.assign({}, n), {
                    signedURL: n.signedURL ? `${this.url}${n.signedURL}` : null,
                  })
                ),
                error: null,
              };
            } catch (n) {
              return { data: null, error: n };
            }
          });
        }
        download(n) {
          return hn(this, void 0, void 0, function* () {
            try {
              const e = this._getFinalPath(n),
                t = yield an(this.fetch, `${this.url}/object/${e}`, {
                  headers: this.headers,
                  noResolveJson: !0,
                });
              return { data: yield t.blob(), error: null };
            } catch (n) {
              return { data: null, error: n };
            }
          });
        }
        getPublicUrl(n) {
          try {
            const e = this._getFinalPath(n),
              t = `${this.url}/object/public/${e}`;
            return { data: { publicURL: t }, error: null, publicURL: t };
          } catch (n) {
            return { data: null, error: n, publicURL: null };
          }
        }
        remove(n) {
          return hn(this, void 0, void 0, function* () {
            try {
              return {
                data: yield cn(
                  this.fetch,
                  `${this.url}/object/${this.bucketId}`,
                  { prefixes: n },
                  { headers: this.headers }
                ),
                error: null,
              };
            } catch (n) {
              return { data: null, error: n };
            }
          });
        }
        list(n, e, t) {
          return hn(this, void 0, void 0, function* () {
            try {
              const r = Object.assign(Object.assign(Object.assign({}, un), e), {
                prefix: n || "",
              });
              return {
                data: yield An(
                  this.fetch,
                  `${this.url}/object/list/${this.bucketId}`,
                  r,
                  { headers: this.headers },
                  t
                ),
                error: null,
              };
            } catch (n) {
              return { data: null, error: n };
            }
          });
        }
        _getFinalPath(n) {
          return `${this.bucketId}/${n}`;
        }
        _removeEmptyFolders(n) {
          return n.replace(/^\/|\/$/g, "").replace(/\/+/g, "/");
        }
      }
      class mn extends class {
        constructor(n, e = {}, t) {
          (this.url = n),
            (this.headers = Object.assign(Object.assign({}, tn), e)),
            (this.fetch = dn(t));
        }
        listBuckets() {
          return ln(this, void 0, void 0, function* () {
            try {
              return {
                data: yield an(this.fetch, `${this.url}/bucket`, {
                  headers: this.headers,
                }),
                error: null,
              };
            } catch (n) {
              return { data: null, error: n };
            }
          });
        }
        getBucket(n) {
          return ln(this, void 0, void 0, function* () {
            try {
              return {
                data: yield an(this.fetch, `${this.url}/bucket/${n}`, {
                  headers: this.headers,
                }),
                error: null,
              };
            } catch (n) {
              return { data: null, error: n };
            }
          });
        }
        createBucket(n, e = { public: !1 }) {
          return ln(this, void 0, void 0, function* () {
            try {
              return {
                data: (yield An(
                  this.fetch,
                  `${this.url}/bucket`,
                  { id: n, name: n, public: e.public },
                  { headers: this.headers }
                )).name,
                error: null,
              };
            } catch (n) {
              return { data: null, error: n };
            }
          });
        }
        updateBucket(n, e) {
          return ln(this, void 0, void 0, function* () {
            try {
              const t = yield (function (n, e, t, r, o) {
                return rn(this, void 0, void 0, function* () {
                  return sn(n, "PUT", e, r, undefined, t);
                });
              })(
                this.fetch,
                `${this.url}/bucket/${n}`,
                { id: n, name: n, public: e.public },
                { headers: this.headers }
              );
              return { data: t, error: null };
            } catch (n) {
              return { data: null, error: n };
            }
          });
        }
        emptyBucket(n) {
          return ln(this, void 0, void 0, function* () {
            try {
              return {
                data: yield An(
                  this.fetch,
                  `${this.url}/bucket/${n}/empty`,
                  {},
                  { headers: this.headers }
                ),
                error: null,
              };
            } catch (n) {
              return { data: null, error: n };
            }
          });
        }
        deleteBucket(n) {
          return ln(this, void 0, void 0, function* () {
            try {
              return {
                data: yield cn(
                  this.fetch,
                  `${this.url}/bucket/${n}`,
                  {},
                  { headers: this.headers }
                ),
                error: null,
              };
            } catch (n) {
              return { data: null, error: n };
            }
          });
        }
      } {
        constructor(n, e = {}, t) {
          super(n, e, t);
        }
        from(n) {
          return new gn(this.url, this.headers, n, this.fetch);
        }
      }
      class fn {
        constructor(n, { headers: e = {}, customFetch: t } = {}) {
          (this.url = n),
            (this.headers = e),
            (this.fetch = ((n) => {
              let e;
              return (
                (e =
                  n ||
                  ("undefined" == typeof fetch
                    ? (...n) => {
                        return (
                          (e = void 0),
                          (t = void 0),
                          (o = function* () {
                            return yield (yield s
                              .e(98)
                              .then(s.t.bind(s, 98, 23))).fetch(...n);
                          }),
                          new ((r = void 0) || (r = Promise))(function (n, i) {
                            function s(n) {
                              try {
                                A(o.next(n));
                              } catch (n) {
                                i(n);
                              }
                            }
                            function a(n) {
                              try {
                                A(o.throw(n));
                              } catch (n) {
                                i(n);
                              }
                            }
                            function A(e) {
                              var t;
                              e.done
                                ? n(e.value)
                                : ((t = e.value),
                                  t instanceof r
                                    ? t
                                    : new r(function (n) {
                                        n(t);
                                      })).then(s, a);
                            }
                            A((o = o.apply(e, t || [])).next());
                          })
                        );
                        var e, t, r, o;
                      }
                    : fetch)),
                (...n) => e(...n)
              );
            })(t));
        }
        setAuth(n) {
          this.headers.Authorization = `Bearer ${n}`;
        }
        invoke(n, e) {
          return (
            (t = this),
            (r = void 0),
            (i = function* () {
              try {
                const { headers: t, body: r } = null != e ? e : {},
                  o = yield this.fetch(`${this.url}/${n}`, {
                    method: "POST",
                    headers: Object.assign({}, this.headers, t),
                    body: r,
                  }),
                  i = o.headers.get("x-relay-error");
                if (i && "true" === i)
                  return { data: null, error: new Error(yield o.text()) };
                let s;
                const { responseType: a } = null != e ? e : {};
                return (
                  (s =
                    a && "json" !== a
                      ? "arrayBuffer" === a
                        ? yield o.arrayBuffer()
                        : "blob" === a
                        ? yield o.blob()
                        : yield o.text()
                      : yield o.json()),
                  { data: s, error: null }
                );
              } catch (n) {
                return { data: null, error: n };
              }
            }),
            new ((o = void 0) || (o = Promise))(function (n, e) {
              function s(n) {
                try {
                  A(i.next(n));
                } catch (n) {
                  e(n);
                }
              }
              function a(n) {
                try {
                  A(i.throw(n));
                } catch (n) {
                  e(n);
                }
              }
              function A(e) {
                var t;
                e.done
                  ? n(e.value)
                  : ((t = e.value),
                    t instanceof o
                      ? t
                      : new o(function (n) {
                          n(t);
                        })).then(s, a);
              }
              A((i = i.apply(t, r || [])).next());
            })
          );
          var t, r, o, i;
        }
      }
      var bn = function (n, e, t, r) {
        return new (t || (t = Promise))(function (o, i) {
          function s(n) {
            try {
              A(r.next(n));
            } catch (n) {
              i(n);
            }
          }
          function a(n) {
            try {
              A(r.throw(n));
            } catch (n) {
              i(n);
            }
          }
          function A(n) {
            var e;
            n.done
              ? o(n.value)
              : ((e = n.value),
                e instanceof t
                  ? e
                  : new t(function (n) {
                      n(e);
                    })).then(s, a);
          }
          A((r = r.apply(n, e || [])).next());
        });
      };
      const wn = {
        schema: "public",
        autoRefreshToken: !0,
        persistSession: !0,
        detectSessionInUrl: !0,
        multiTab: !0,
        headers: n,
      };
      class En {
        constructor(e, t, r) {
          if (((this.supabaseUrl = e), (this.supabaseKey = t), !e))
            throw new Error("supabaseUrl is required.");
          if (!t) throw new Error("supabaseKey is required.");
          const o = e.replace(/\/$/, ""),
            i = Object.assign(Object.assign({}, wn), r);
          if (
            ((this.restUrl = `${o}/rest/v1`),
            (this.realtimeUrl = `${o}/realtime/v1`.replace("http", "ws")),
            (this.authUrl = `${o}/auth/v1`),
            (this.storageUrl = `${o}/storage/v1`),
            o.match(/(supabase\.co)|(supabase\.in)/))
          ) {
            const n = o.split(".");
            this.functionsUrl = `${n[0]}.functions.${n[1]}.${n[2]}`;
          } else this.functionsUrl = `${o}/functions/v1`;
          (this.schema = i.schema),
            (this.multiTab = i.multiTab),
            (this.fetch = i.fetch),
            (this.headers = Object.assign(
              Object.assign({}, n),
              null == r ? void 0 : r.headers
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
          return new fn(this.functionsUrl, {
            headers: this._getAuthHeaders(),
            customFetch: this.fetch,
          });
        }
        get storage() {
          return new mn(this.storageUrl, this._getAuthHeaders(), this.fetch);
        }
        from(n) {
          const e = `${this.restUrl}/${n}`;
          return new en(e, {
            headers: this._getAuthHeaders(),
            schema: this.schema,
            realtime: this.realtime,
            table: n,
            fetch: this.fetch,
            shouldThrowOnError: this.shouldThrowOnError,
          });
        }
        rpc(n, e, { head: t = !1, count: r = null } = {}) {
          return this._initPostgRESTClient().rpc(n, e, { head: t, count: r });
        }
        removeAllSubscriptions() {
          return bn(this, void 0, void 0, function* () {
            const n = this.getSubscriptions().slice(),
              e = n.map((n) => this.removeSubscription(n));
            return (yield Promise.all(e)).map(({ error: e }, t) => ({
              data: { subscription: n[t] },
              error: e,
            }));
          });
        }
        removeSubscription(n) {
          return bn(this, void 0, void 0, function* () {
            const { error: e } = yield this._closeSubscription(n),
              t = this.getSubscriptions(),
              r = t.filter((n) => n.isJoined()).length;
            return (
              0 === t.length && (yield this.realtime.disconnect()),
              { data: { openSubscriptions: r }, error: e }
            );
          });
        }
        _closeSubscription(n) {
          return bn(this, void 0, void 0, function* () {
            let e = null;
            if (!n.isClosed()) {
              const { error: t } = yield this._unsubscribeSubscription(n);
              e = t;
            }
            return this.realtime.remove(n), { error: e };
          });
        }
        _unsubscribeSubscription(n) {
          return new Promise((e) => {
            n.unsubscribe()
              .receive("ok", () => e({ error: null }))
              .receive("error", (n) => e({ error: n }))
              .receive("timeout", () => e({ error: new Error("timed out") }));
          });
        }
        getSubscriptions() {
          return this.realtime.channels;
        }
        _initSupabaseAuthClient({
          autoRefreshToken: n,
          persistSession: e,
          detectSessionInUrl: t,
          localStorage: r,
          headers: o,
          fetch: i,
          cookieOptions: s,
          multiTab: a,
        }) {
          const A = {
            Authorization: `Bearer ${this.supabaseKey}`,
            apikey: `${this.supabaseKey}`,
          };
          return new C({
            url: this.authUrl,
            headers: Object.assign(Object.assign({}, o), A),
            autoRefreshToken: n,
            persistSession: e,
            detectSessionInUrl: t,
            localStorage: r,
            fetch: i,
            cookieOptions: s,
            multiTab: a,
          });
        }
        _initRealtimeClient(n) {
          return new Q(
            this.realtimeUrl,
            Object.assign(Object.assign({}, n), {
              params: Object.assign(
                Object.assign({}, null == n ? void 0 : n.params),
                { apikey: this.supabaseKey }
              ),
            })
          );
        }
        _initPostgRESTClient() {
          return new j(this.restUrl, {
            headers: this._getAuthHeaders(),
            schema: this.schema,
            fetch: this.fetch,
            throwOnError: this.shouldThrowOnError,
          });
        }
        _getAuthHeaders() {
          var n, e;
          const t = Object.assign({}, this.headers),
            r =
              null !==
                (e =
                  null === (n = this.auth.session()) || void 0 === n
                    ? void 0
                    : n.access_token) && void 0 !== e
                ? e
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
              : window.addEventListener("storage", (n) => {
                  var e, t, r;
                  if ("supabase.auth.token" === n.key) {
                    const o = JSON.parse(String(n.newValue)),
                      i =
                        null !==
                          (t =
                            null ===
                              (e = null == o ? void 0 : o.currentSession) ||
                            void 0 === e
                              ? void 0
                              : e.access_token) && void 0 !== t
                          ? t
                          : void 0,
                      s =
                        null === (r = this.auth.session()) || void 0 === r
                          ? void 0
                          : r.access_token;
                    i
                      ? !s && i
                        ? this._handleTokenChanged("SIGNED_IN", i, "STORAGE")
                        : s !== i &&
                          this._handleTokenChanged(
                            "TOKEN_REFRESHED",
                            i,
                            "STORAGE"
                          )
                      : this._handleTokenChanged("SIGNED_OUT", i, "STORAGE");
                  }
                });
          } catch (n) {
            return console.error("_listenForMultiTabEvents", n), null;
          }
        }
        _listenForAuthEvents() {
          let { data: n } = this.auth.onAuthStateChange((n, e) => {
            this._handleTokenChanged(
              n,
              null == e ? void 0 : e.access_token,
              "CLIENT"
            );
          });
          return n;
        }
        _handleTokenChanged(n, e, t) {
          ("TOKEN_REFRESHED" !== n && "SIGNED_IN" !== n) ||
          this.changedAccessToken === e
            ? ("SIGNED_OUT" !== n && "USER_DELETED" !== n) ||
              (this.realtime.setAuth(this.supabaseKey),
              "STORAGE" == t && this.auth.signOut())
            : (this.realtime.setAuth(e),
              "STORAGE" == t && this.auth.setAuth(e),
              (this.changedAccessToken = e));
        }
      }
      var Bn = s(379),
        Cn = s.n(Bn),
        vn = s(795),
        yn = s.n(vn),
        kn = s(569),
        xn = s.n(kn),
        _n = s(565),
        Sn = s.n(_n),
        Tn = s(216),
        jn = s.n(Tn),
        On = s(589),
        $n = s.n(On),
        In = s(265),
        Dn = {};
      (Dn.styleTagTransform = $n()),
        (Dn.setAttributes = Sn()),
        (Dn.insert = xn().bind(null, "head")),
        (Dn.domAPI = yn()),
        (Dn.insertStyleElement = jn()),
        Cn()(In.Z, Dn),
        In.Z && In.Z.locals && In.Z.locals;
      const Rn = new En(
        "https://rsfcqodmucagrxohmkgx.supabase.co",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InJzZmNxb2RtdWNhZ3J4b2hta2d4Iiwicm9sZSI6ImFub24iLCJpYXQiOjE2NjA5MjY5NDksImV4cCI6MTk3NjUwMjk0OX0.emUFAjUIpou6UOyQlIzvlvv9E4tClWoluh6SOoMNc8I",
        void 0
      );
      console.log(Rn.auth.user()),
        Rn.auth.user()
          ? (console.log(Rn.auth.user().email),
            document.getElementById("formie").classList.remove("hidden"),
            document.getElementById("notlogged").classList.add("hidden"))
          : (document.getElementById("formie").classList.add("hidden"),
            document.getElementById("notlogged").classList.remove("hidden")),
        console.log("hiyo");
      var Pn = [];
      document.getElementById("files").addEventListener("change", function (n) {
        Pn = n.target.files;
      }),
        document
          .getElementById("send")
          .addEventListener("click", async function () {
            if (0 != Pn.length)
              for (let n = 0; n < Pn.length; n++) {
                const { data: e, error: t } = await Rn.storage
                  .from("forms")
                  .upload(
                    document.getElementById("level").value +
                      "/" +
                      document.getElementById("folder").value +
                      "/" +
                      Pn[n].name,
                    Pn[n],
                    { cacheControl: "3600", upsert: !1 }
                  );
              }
          }),
        (window.openNav = function () {
          document.getElementById("mySidenav").style.width = "250px";
        }),
        (window.closeNav = function () {
          document.getElementById("mySidenav").style.width = "0";
        }),
        (window.logout = async function () {
          await Rn.auth.signOut(), window.location.replace("index.html");
        }),
        (window.accessAdmin = function () {
          document.getElementById("admin").classList.contains("hidden")
            ? JSAlert.alert(
                "<code>Error:- You have not been granted Admin access</code>",
                null,
                JSAlert.Icons.Failed
              )
            : (window.location.href = "admin.html");
        });
    })();
})();
