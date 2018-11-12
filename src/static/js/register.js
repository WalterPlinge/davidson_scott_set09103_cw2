var register_modal = document.getElementById('register_modal');
var register_username = document.getElementById('register_username');
var register_email = document.getElementById('register_email');
var register_password = document.getElementById('register_password');
var register_password2 = document.getElementById('register_password2');
var register_submit = document.getElementById('register_submit');

// When the user clicks anywhere outside of the modal, close it
window.onclick = function (event) {
    if (event.target == register_modal) {
        register_modal.style.display = 'none';
    }
};

register_password.onchange = function () {
    if (register_password.value == register_password2.value) {
        register_password2.classList.remove('btn_outline-danger');
        register_password2.classList.add('btn_outline-success');
        register_submit.removeAttribute('disabled');
    } else {
        register_password2.classList.remove('btn_outline-success');
        register_password2.classList.add('btn_outline-danger');
        register_submit.attributes.add('disabled');
    }
};

register_password2.onchange = function () {
    if (register_password.value == register_password2.value) {
        register_password2.classList.remove('btn_outline-danger');
        register_password2.classList.add('btn_outline-success');
        register_submit.removeAttribute('disabled');
    } else {
        register_password2.classList.remove('btn_outline-success');
        register_password2.classList.add('btn_outline-danger');
        register_submit.attributes.add('disabled');
    }
};
