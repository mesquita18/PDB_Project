// Toast Notification Manager
class Toast {
    constructor() {
        this.container = this.createContainer();
    }

    createContainer() {
        let container = document.getElementById('toast-container');
        if (!container) {
            container = document.createElement('div');
            container.id = 'toast-container';
            container.className = 'toast-container';
            document.body.appendChild(container);
        }
        return container;
    }

    show(message, type = 'success', duration = 4000) {
        const toast = document.createElement('div');
        // Garantir que a classe de tipo é válida
        const validTypes = ['success', 'error', 'info', 'warning'];
        const toastType = validTypes.includes(type) ? type : 'success';
        toast.className = `toast ${toastType}`;

        // Determinar cores baseado no tipo
        let bgColor = '#28a745';
        let textColor = 'white';
        let borderColor = '#20c997';
        let icon = '✓';

        if (toastType === 'error') {
            bgColor = '#dc3545';
            textColor = 'white';
            borderColor = '#ff6b6b';
            icon = '✕';
        } else if (toastType === 'info') {
            bgColor = '#007bff';
            textColor = 'white';
            borderColor = '#4dabf7';
            icon = 'ℹ';
        } else if (toastType === 'warning') {
            bgColor = '#ffc107';
            textColor = '#000';
            borderColor = '#ff9800';
            icon = '⚠';
        }

        // Aplicar inline styles como fallback
        toast.style.backgroundColor = bgColor;
        toast.style.color = textColor;
        toast.style.borderLeftColor = borderColor;

        toast.innerHTML = `
            <span class="toast-icon" style="color: ${textColor};">${icon}</span>
            <span class="toast-message" style="color: ${textColor};">${message}</span>
            <button class="toast-close" type="button" style="color: ${textColor};">&times;</button>
        `;

        // Adicionar evento ao botão de fechar
        toast.querySelector('.toast-close').addEventListener('click', () => {
            this.remove(toast);
        });

        this.container.appendChild(toast);

        // Auto-remover após duration
        if (duration > 0) {
            setTimeout(() => {
                this.remove(toast);
            }, duration);
        }

        return toast;
    }

    remove(toast) {
        toast.classList.add('hide');
        setTimeout(() => {
            toast.remove();
        }, 300);
    }

    success(message, duration = 4000) {
        return this.show(message, 'success', duration);
    }

    error(message, duration = 4000) {
        return this.show(message, 'error', duration);
    }

    info(message, duration = 4000) {
        return this.show(message, 'info', duration);
    }

    warning(message, duration = 4000) {
        return this.show(message, 'warning', duration);
    }
}

// Instância global
const toast = new Toast();

// Auto-mostrar toasts do Django messages ao carregar página
document.addEventListener('DOMContentLoaded', function() {
    const messagesContainer = document.getElementById('django-messages');
    if (messagesContainer) {
        const messages = messagesContainer.querySelectorAll('li');
        messages.forEach(message => {
            let type = message.getAttribute('data-type') || 'info';
            // Normalizar o tipo
            const validTypes = ['success', 'error', 'info', 'warning'];
            if (!validTypes.includes(type.toLowerCase())) {
                type = 'info';
            }
            const text = message.textContent.trim();
            if (text) {
                toast.show(text, type.toLowerCase());
            }
        });
    }
});
