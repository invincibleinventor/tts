import './styles.css'
import { ExportToCsv } from 'export-to-csv';

const supabase = createClient(process.env.URL, process.env.ANON);
import { createClient } from "@supabase/supabase-js";

var queryString = decodeURIComponent(window.location.search);
queryString = queryString.substring(1);
var queries = queryString.split("&");
var id = queries[0].slice(queries[0].indexOf("=") + 1);
var table = queries[1].slice(queries[1].indexOf("=") + 1);


async function logout() {
  await supabase.auth.signOut();
  window.location.replace("index.html");
}
var admin;
if (supabase.auth.user()) {
    console.log(supabase.auth.user().email);
    console.log(process.env.ADMINS.split(","));
  
  
    for (var ex in process.env.ADMINS.split(",")){
    if (supabase.auth.user().email == process.env.ADMINS.split(",")[ex]) {
      
      document.getElementById("admin").classList.remove("hidden");
      console.log(ex)
       admin=true;
      break;
    } else {
      document.getElementById("admin").classList.add("hidden");
      window.location.replace('main.html');
    }
  }
    document.getElementById("formie").classList.remove("hidden");
    document.getElementById("notlogged").classList.add("hidden");
  } else {
    document.getElementById("formie").classList.add("hidden");
    document.getElementById("notlogged").classList.remove("hidden");
  }


  function openNav() {
    document.getElementById("mySidenav").style.width = "250px";
  }
  
  function closeNav() {
    document.getElementById("mySidenav").style.width = "0";
  }


  if (admin) {
    async function settitle(){
        const { data, error } = await supabase.from("Forms").select();
        var ar = data;
        document.getElementById('htitle').innerHTML=ar[id-1].title;
    }
    async function fetchdata() {
      const { data, error } = await supabase.from(table).select();
      var br = data;
        console.log(br)
    convertJsontoHtmlTable(br)
    }

    function convertJsontoHtmlTable(employess)
    {

        //Getting value for table header
        // {'EmployeeID', 'EmployeeName', 'Address' , 'City','Country'}
        var tablecolumns = [];
        for (var i = 0; i < employess.length; i++) {
            for (var key in employess[i]) {
                if (tablecolumns.indexOf(key) === -1) {
                    tablecolumns.push(key);
                }
            }
        }

        //Creating html table and adding class to it
        var tableemployee = document.createElement("table");
        tableemployee.classList.add("table");
        tableemployee.classList.add("table-striped");
        tableemployee.classList.add("table-bordered");
        tableemployee.classList.add("table-hover")

        //Creating header of the HTML table using
        //tr
        var tr = tableemployee.insertRow(-1);

        for (var i = 0; i < tablecolumns.length; i++) {
            //header
            var th = document.createElement("th");
            th.innerHTML = tablecolumns[i];
            tr.appendChild(th);
        }

        // Add employee JSON data in table as tr or rows
        for (var i = 0; i < employess.length; i++) {
            tr = tableemployee.insertRow(-1);
            for (var j = 0; j < tablecolumns.length; j++) {
                var tabCell = tr.insertCell(-1);
                tabCell.innerHTML = employess[i][tablecolumns[j]];
            }
        }

        //Final step , append html table to the container div
        var employeedivcontainer = document.getElementById("employeedivcontainer");
        employeedivcontainer.innerHTML = "";
        employeedivcontainer.appendChild(tableemployee);
    }
  settitle();
    fetchdata();
  }
  
  async function downloaddata(){
    const { data, error } = await supabase.from(table).select();
    const options = { 
        fieldSeparator: ',',
        quoteStrings: '"',
        decimalSeparator: '.',
        showLabels: true, 
        showTitle: false,
        filename: document.getElementById('htitle').innerText,
        useTextFile: false,
        useBom: true,
        useKeysAsHeaders: true,
        // headers: ['Column 1', 'Column 2', etc...] <-- Won't work with useKeysAsHeaders present!
      };
      const csvExporter = new ExportToCsv(options);

      csvExporter.generateCsv(data);
      

  }


  window.openNav = openNav;
  window.closeNav = closeNav;
  
  window.logout = logout;
  window.downloaddata = downloaddata;
  