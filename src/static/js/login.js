var login_modal = document.getElementById('login_modal');

// When the user clicks anywhere outside of the modal, close it
window.onclick = function (event) {
    console.log("clicked");
    if (event.target == login_modal) {
        console.log("true");
        login_modal.style.display = 'none';
    }
}