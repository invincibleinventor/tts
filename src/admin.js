import './styles.css'

const supabase = createClient(process.env.URL, process.env.ANON);
import { createClient } from "@supabase/supabase-js";

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
    async function fetchdata() {
      const { data, error } = await supabase.from("Forms").select();
      var br = data;
  
      for (var sh = 0; sh <= br.length - 1; sh++) {
        document
          .getElementById("formlist")
          .insertAdjacentHTML(
            "beforeend",
            `<a href="viewform.html?id=${br[sh].id}&table=${br[sh].Table}" class="px-6 py-2   w-full rounded-t-lg font-inter text-sm md:text-md flex flex-row content-center items-center "><span class="iconify mr-2 inline-flex my-auto items-center content-center" data-icon="ep:document"></span><span class="my-auto items-center content-center inline-flex">${br[sh].title}</span><span class="iconify ml-auto  inline-flex my-auto items-center content-center lg:hidden" data-icon="ep:arrow-right"></span></a>`
          );
      }
    }
  
    fetchdata();
  }
  
  window.openNav = openNav;
  window.closeNav = closeNav;
  
  window.logout = logout;
  