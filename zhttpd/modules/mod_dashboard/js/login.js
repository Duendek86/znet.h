// Login page logic
(function () {
    const loginForm = document.getElementById('loginForm');
    const usernameInput = document.getElementById('username');
    const passwordInput = document.getElementById('password');
    const errorMsg = document.getElementById('errorMsg');
    const loginBtn = loginForm.querySelector('.login-btn');
    const btnText = loginBtn.querySelector('.btn-text');
    const btnLoader = loginBtn.querySelector('.btn-loader');

    // Check if already logged in
    const credentials = sessionStorage.getItem('dashboardAuth');
    if (credentials) {
        // Verify credentials are still valid
        verifyAuth(credentials).then(valid => {
            if (valid) {
                window.location.href = 'dashboard.html';
            }
        });
    }

    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();

        const username = usernameInput.value.trim();
        const password = passwordInput.value.trim();

        if (!username || !password) {
            showError('Por favor ingresa usuario y contraseña');
            return;
        }

        // Disable form
        setLoading(true);
        hideError();

        // Create Basic Auth credentials
        const credentials = btoa(`${username}:${password}`);

        // Test authentication with the API
        const isValid = await verifyAuth(credentials);

        if (isValid) {
            // Store credentials
            sessionStorage.setItem('dashboardAuth', credentials);

            // Redirect to dashboard
            window.location.href = 'dashboard.html';
        } else {
            showError('Usuario o contraseña incorrectos');
            setLoading(false);
        }
    });

    async function verifyAuth(credentials) {
        try {
            const response = await fetch('/api/auth/check', {
                headers: {
                    'Authorization': `Basic ${credentials}`,
                    'X-Requested-With': 'XMLHttpRequest'  // Mark as AJAX to prevent browser dialog
                }
            });
            return response.ok;
        } catch (error) {
            console.error('Auth verification error:', error);
            return false;
        }
    }

    function showError(message) {
        errorMsg.textContent = message;
        errorMsg.classList.add('show');
    }

    function hideError() {
        errorMsg.classList.remove('show');
    }

    function setLoading(loading) {
        loginBtn.disabled = loading;
        if (loading) {
            btnText.style.display = 'none';
            btnLoader.style.display = 'inline';
        } else {
            btnText.style.display = 'inline';
            btnLoader.style.display = 'none';
        }
    }
})();
