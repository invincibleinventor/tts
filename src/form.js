import { Account, Query, Databases, Client } from "appwrite";
const client = new Client();
import "./styles.css";
import JSAlert from "js-alert";

import { createClient } from "@supabase/supabase-js";

// Create a single supabase client for interacting with your database
const supabase = createClient(process.env.URL, process.env.ANON);
if (supabase.auth.user()) {
  document.getElementById("formie").classList.remove("hidden");
  document.getElementById("notlogged").classList.add("hidden");
} else {
  document.getElementById("formie").classList.add("hidden");
  document.getElementById("notlogged").classList.remove("hidden");
  document.getElementById("lex").innerHTML = "Not Logged In";
}

var arr = [];

var queryString = decodeURIComponent(window.location.search);
queryString = queryString.substring(1);
var queries = queryString.split("&");
var id = queries[0].slice(queries[0].indexOf("=") + 1);
var table = queries[1].slice(queries[1].indexOf("=") + 1);

function addDate() {
  console.log("date added");
}

function toUpper(str) {
  return str
    .toLowerCase()
    .split(" ")
    .map(function (word) {
      return word[0].toUpperCase() + word.substr(1);
    })
    .join(" ");
}

function addVal(c) {
  var cb = toUpper(c.replaceAll("_", " "));
  var a = `<div class="col-span-6 sm:col-span-3 w-auto py-2 ">
  <label for="${c}" class="block text-sm font-medium text-gray-700 pt-4 mb-1">${cb}</label>
  <input type="text" id="${c}" autocomplete="given-name" class=" focus:ring-blue-500  focus:border-blue-500 block w-full shadow-sm sm:text-sm border border-neutral-200 py-2 px-3 outline-none">
</div>`;
  document.getElementById("elelist").insertAdjacentHTML("afterbegin", a);
  arr.push(c);
}

async function sr() {
  const { data, error } = await supabase.from("Forms").select();
  document.getElementById("title").innerHTML = data[id - 1].title;
  document.getElementById("description").innerHTML = data[id - 1].description;
}
sr();

function onsubmitted() {
  document.getElementById("formie").classList.add("hidden");
  document.getElementById("notlogged").classList.remove("hidden");
  document.getElementById("lex").innerHTML = "Already Submitted";
}

async function fetchdata() {
  const { data, error } = await supabase.from(table).select();
  for (let i in data) {
    if (data[i].uid == window.localStorage.getItem("email")) {
      onsubmitted();
    }
  }
  var brr = Object.keys(data[0]);
  console.log(brr);
  brr.pop();
  brr.reverse();

  console.log(brr);

  for (let i in brr) {
    let c = brr[i];
    addVal(c);
  }

  async function pushdata() {
    const { data, error } = await supabase.from(table).select();
    var obj = {
      uid: window.localStorage.getItem("email"),
    };

    var brr = Object.keys(data[0]);
    console.log(brr);
    brr.pop();
    brr.reverse();
    for (let i in brr) {
      obj[brr[i]] = document.getElementById(brr[i]).value;
    }

    const { d, e } = await supabase.from(table).insert(obj);
    if (d) {
      onsubmitted();
      JSAlert.alert("Submitted Successfully", null, JSAlert.Icons.Success);
    }
  }

  document.getElementById("submit").addEventListener("click", (e) => {
    e.preventDefault();
    pushdata();

    return false;
  });

  return false;
}

fetchdata();

window.addDate = addDate;
window.addVal = addVal;