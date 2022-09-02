const path = require("path");
const Dotenv = require("dotenv-webpack");

const HtmlWebpackPlugin = require("html-webpack-plugin");
let htmlPageNames = [
  "index",
  "main",
  "forms",
  "form",
  "upload",
  "admin",
  "viewform",
];
var WebpackObfuscator = require("webpack-obfuscator");

let multipleHtmlPlugins = htmlPageNames.map((name) => {
  return new HtmlWebpackPlugin({
    template: `./src/${name}.html`, // relative path to the HTML files
    filename: `${name}.html`, // output HTML files
    chunks: [`${name}`], // respective JS files
  });
});
module.exports = {
  mode: "development",
  entry: {
    index: "./src/index.js",
    main: "./src/main.js",
    forms: "./src/forms.js",
    form: "./src/form.js",
    upload: "./src/upload.js",
    admin: "./src/admin.js",
    viewform: "./src/viewform.js",
  },

  devServer: {
    static: {
      directory: path.resolve(__dirname, "dist"),
    },
    port: 3000,
    open: true,
    hot: true,
    compress: true,
    historyApiFallback: true,
  },
  devtool: process.env.SOURCE_MAP ? "inline-source-map" : "hidden-source-map",

  plugins: [
    new Dotenv(),
    new HtmlWebpackPlugin({
      template: "./src/index.html",
      excludeChunks: ["main", "forms", "form", "upload", "admin", "viewform"],
    }),
  ].concat(multipleHtmlPlugins),
  module: {
    rules: [
      {
        test: /\.css$/i,
        include: path.resolve(__dirname, "src"),
        use: ["style-loader", "css-loader", "postcss-loader"],
      },
    ],
  },
};
