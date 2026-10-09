// Xu ly giao dien nguoi dung an toan
function validateForm() {
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;

    if (email.length === 0) {
        alert('Vui long nhap email');
        return false;
    }

    if (password.length < 6) {
        alert('Mat khau phai it nhat 6 ky tu');
        return false;
    }

    return true;
}

fetch('/api/contact', {
    method: 'POST',
    body: JSON.stringify({ name: 'An', message: 'Xin chao' })
});
