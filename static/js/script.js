document.addEventListener("DOMContentLoaded", function () {
    const loginForm = document.getElementById("loginForm");

    if (loginForm) {
        loginForm.addEventListener("submit", function (event) {
            event.preventDefault();

            const userID = document.getElementById("userID").value;
            const password = document.getElementById("password").value;

            // Simulación de base de datos de usuarios (esto debería ir en un backend real)
            const users = [
                { id: "admin", password: "1234" },
                { id: "empleado1", password: "empleado123" }
            ];

            // Verificar si las credenciales son correctas
            const user = users.find(u => u.id === userID && u.password === password);

            if (user) {
                // Guardar sesión en localStorage (esto no es seguro para producción)
                localStorage.setItem("loggedIn", "true");
                localStorage.setItem("userID", userID);

                // Redirigir al panel de administrador
                window.location.href = "admin.html";
            } else {
                alert("Usuario o contraseña incorrectos.");
            }
        });
    }

    // Verificar si el usuario ya está logueado en otras páginas
    if (window.location.pathname.includes("admin.html")) {
        const loggedIn = localStorage.getItem("loggedIn");

        if (!loggedIn) {
            alert("Debes iniciar sesión primero.");
            window.location.href = "index.html";
        }
    }

    // Cerrar sesión
    const logoutLink = document.querySelector(".nav-link.text-danger");
    if (logoutLink) {
        logoutLink.addEventListener("click", function (event) {
            event.preventDefault();
            localStorage.removeItem("loggedIn");
            localStorage.removeItem("userID");
            window.location.href = "index.html";
        });
    }
});
