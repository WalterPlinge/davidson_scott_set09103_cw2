var loginmodal = document.getElementById('login');

// When the user clicks anywhere outside of the modal, close it
window.onclick = function (event) {
    if (event.target == loginmodal) {
        loginmodal.style.display = "none";
    }
}