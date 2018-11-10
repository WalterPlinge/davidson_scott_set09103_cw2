var registermodal = document.getElementById('register');

// When the user clicks anywhere outside of the modal, close it
window.onclick = function (event) {
    if (event.target == register) {
        register.style.display = "none";
    }
}