// Helper to show dynamic Toast notifications
function showToast(message, type = "success") {
    let container = document.getElementById("toast-container");
    if (!container) {
        container = document.createElement("div");
        container.id = "toast-container";
        container.className = "toast-container";
        document.body.appendChild(container);
    }
    
    const toast = document.createElement("div");
    toast.className = `toast toast-${type}`;
    
    // Choose icon based on type
    let icon = `<svg style="width:18px;height:18px;flex-shrink:0" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>`;
    if (type === "success") {
        icon = `<svg style="width:18px;height:18px;flex-shrink:0;color:var(--color-success)" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>`;
    } else if (type === "error") {
        icon = `<svg style="width:18px;height:18px;flex-shrink:0;color:var(--color-danger)" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>`;
    } else if (type === "warning") {
        icon = `<svg style="width:18px;height:18px;flex-shrink:0;color:var(--color-warning)" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /></svg>`;
    }
    
    toast.innerHTML = `${icon}<span>${message}</span>`;
    container.appendChild(toast);
    
    // Auto-remove after 4 seconds
    setTimeout(() => {
        toast.style.opacity = "0";
        toast.style.transform = "translateY(50px)";
        toast.style.transition = "all 0.4s ease";
        setTimeout(() => {
            toast.remove();
        }, 400);
    }, 4000);
}

// Modal open/close actions
function openModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.style.display = "flex";
    }
}

function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.style.display = "none";
    }
}

// Copy content to clipboard helper
function copyToClipboard(text, buttonElement) {
    navigator.clipboard.writeText(text).then(() => {
        showToast("Copied to clipboard!");
        
        // Temporarily change icon to checkmark
        if (buttonElement) {
            const originalHTML = buttonElement.innerHTML;
            buttonElement.innerHTML = `<svg style="width:18px;height:18px;color:var(--color-success)" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" /></svg>`;
            setTimeout(() => {
                buttonElement.innerHTML = originalHTML;
            }, 2000);
        }
    }).catch(err => {
        showToast("Failed to copy secret.", "error");
    });
}

// Mobile sidebar drawer menu toggle listeners
document.addEventListener("DOMContentLoaded", function() {
    const menuToggle = document.getElementById("menu-toggle-btn");
    const sidebarClose = document.getElementById("sidebar-close-btn");
    const sidebarOverlay = document.getElementById("sidebar-overlay");
    const sidebar = document.querySelector(".sidebar");

    if (menuToggle && sidebar) {
        menuToggle.addEventListener("click", function() {
            sidebar.classList.add("open");
            if (sidebarOverlay) sidebarOverlay.classList.add("active");
        });
    }

    if (sidebarClose && sidebar) {
        sidebarClose.addEventListener("click", function() {
            sidebar.classList.remove("open");
            if (sidebarOverlay) sidebarOverlay.classList.remove("active");
        });
    }

    if (sidebarOverlay && sidebar) {
        sidebarOverlay.addEventListener("click", function() {
            sidebar.classList.remove("open");
            sidebarOverlay.classList.remove("active");
        });
    }
});
