document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
});

function initializeApp() {
    setupMobileNavigation();
    setupAnimations();
    setupFormValidation();
    setupKeyboardShortcuts();
    setupTouchGestures();
    setupServiceWorker();
}

function setupMobileNavigation() {
    const mobileMenuToggle = document.getElementById('mobileMenuToggle');
    const mobileMenu = document.getElementById('mobileMenu');
    const navMenu = document.getElementById('navMenu');
    
    if (mobileMenuToggle && mobileMenu) {
        // Убеждаемся, что мобильное меню скрыто при загрузке
        mobileMenu.classList.remove('active');
        
        mobileMenuToggle.addEventListener('click', function(e) {
            e.stopPropagation();
            toggleMobileMenu();
        });
        
        // Закрыть меню при клике на ссылку
        const mobileLinks = mobileMenu.querySelectorAll('.nav-link');
        mobileLinks.forEach(link => {
            link.addEventListener('click', function() {
                closeMobileMenu();
            });
        });
        
        // Закрыть меню при клике вне его
        document.addEventListener('click', function(e) {
            if (mobileMenu.classList.contains('active') && 
                !mobileMenu.contains(e.target) && 
                !mobileMenuToggle.contains(e.target)) {
                closeMobileMenu();
            }
        });
        
        // Закрыть меню при нажатии Escape
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape' && mobileMenu.classList.contains('active')) {
                closeMobileMenu();
            }
        });
        
        // Обработка изменения размера окна
        window.addEventListener('resize', function() {
            if (window.innerWidth > 768 && mobileMenu.classList.contains('active')) {
                closeMobileMenu();
            }
        });
    }
    
    function toggleMobileMenu() {
        mobileMenu.classList.toggle('active');
        const icon = mobileMenuToggle.querySelector('i');
        if (mobileMenu.classList.contains('active')) {
            icon.className = 'fas fa-times';
            mobileMenuToggle.setAttribute('aria-label', 'Закрыть меню');
            document.body.style.overflow = 'hidden'; // Блокируем скролл
        } else {
            icon.className = 'fas fa-bars';
            mobileMenuToggle.setAttribute('aria-label', 'Открыть меню');
            document.body.style.overflow = ''; // Восстанавливаем скролл
        }
    }
    
    function closeMobileMenu() {
        mobileMenu.classList.remove('active');
        const icon = mobileMenuToggle.querySelector('i');
        icon.className = 'fas fa-bars';
        mobileMenuToggle.setAttribute('aria-label', 'Открыть меню');
        document.body.style.overflow = ''; // Восстанавливаем скролл
    }
}

function setupTouchGestures() {
    let startX = 0;
    let startY = 0;
    let endX = 0;
    let endY = 0;
    
    document.addEventListener('touchstart', function(e) {
        startX = e.touches[0].clientX;
        startY = e.touches[0].clientY;
    });
    
    document.addEventListener('touchend', function(e) {
        endX = e.changedTouches[0].clientX;
        endY = e.changedTouches[0].clientY;
        
        const diffX = startX - endX;
        const diffY = startY - endY;
        
        // Свайп влево для открытия меню (если оно закрыто)
        if (diffX > 50 && Math.abs(diffY) < 50) {
            const mobileMenu = document.getElementById('mobileMenu');
            const mobileMenuToggle = document.getElementById('mobileMenuToggle');
            
            if (mobileMenu && !mobileMenu.classList.contains('active')) {
                mobileMenu.classList.add('active');
                const icon = mobileMenuToggle.querySelector('i');
                icon.className = 'fas fa-times';
                mobileMenuToggle.setAttribute('aria-label', 'Закрыть меню');
                document.body.style.overflow = 'hidden';
            }
        }
        
        // Свайп вправо для закрытия меню (если оно открыто)
        if (diffX < -50 && Math.abs(diffY) < 50) {
            const mobileMenu = document.getElementById('mobileMenu');
            const mobileMenuToggle = document.getElementById('mobileMenuToggle');
            
            if (mobileMenu && mobileMenu.classList.contains('active')) {
                mobileMenu.classList.remove('active');
                const icon = mobileMenuToggle.querySelector('i');
                icon.className = 'fas fa-bars';
                mobileMenuToggle.setAttribute('aria-label', 'Открыть меню');
                document.body.style.overflow = '';
            }
        }
    });
}

function setupServiceWorker() {
    if ('serviceWorker' in navigator) {
        window.addEventListener('load', function() {
            navigator.serviceWorker.register('/sw.js')
                .then(function(registration) {
                    console.log('ServiceWorker registration successful');
                })
                .catch(function(err) {
                    console.log('ServiceWorker registration failed');
                });
        });
    }
}

function setupAnimations() {
    const cards = document.querySelectorAll('.dashboard-card, .password-card, .file-card');
    
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.style.opacity = '1';
                entry.target.style.transform = 'translateY(0)';
            }
        });
    }, { threshold: 0.1 });
    
    cards.forEach(card => {
        card.style.opacity = '0';
        card.style.transform = 'translateY(20px)';
        card.style.transition = 'opacity 0.6s ease, transform 0.6s ease';
        observer.observe(card);
    });
}

function setupFormValidation() {
    const forms = document.querySelectorAll('form');
    
    forms.forEach(form => {
        form.addEventListener('submit', function(e) {
            const requiredFields = form.querySelectorAll('[required]');
            let isValid = true;
            
            requiredFields.forEach(field => {
                if (!field.value.trim()) {
                    isValid = false;
                    highlightField(field, true);
                } else {
                    highlightField(field, false);
                }
            });
            
            if (!isValid) {
                e.preventDefault();
                showNotification('Пожалуйста, заполните все обязательные поля', 'error');
            }
        });
    });
}

function highlightField(field, isError) {
    if (isError) {
        field.style.borderColor = 'var(--error-color)';
        field.style.boxShadow = '0 0 0 3px rgba(239, 68, 68, 0.1)';
    } else {
        field.style.borderColor = '';
        field.style.boxShadow = '';
    }
}

function setupKeyboardShortcuts() {
    document.addEventListener('keydown', function(e) {
        if (e.ctrlKey || e.metaKey) {
            switch(e.key) {
                case 'k':
                    e.preventDefault();
                    if (window.location.pathname === '/passwords') {
                        showAddPasswordModal();
                    } else if (window.location.pathname === '/files') {
                        showUploadFileModal();
                    }
                    break;
                case 's':
                    if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') {
                        return;
                    }
                    e.preventDefault();
                    break;
            }
        }
        
        if (e.key === 'Escape') {
            const modals = document.querySelectorAll('.modal');
            modals.forEach(modal => {
                if (modal.style.display === 'flex') {
                    modal.style.display = 'none';
                }
            });
        }
    });
}

function showNotification(message, type = 'success') {
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    
    const icon = type === 'success' ? 'fas fa-check' : 'fas fa-exclamation-triangle';
    
    notification.innerHTML = `
        <i class="${icon}"></i>
        <span>${message}</span>
    `;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.style.transform = 'translateX(100%)';
        notification.style.opacity = '0';
        setTimeout(() => {
            notification.remove();
        }, 300);
    }, 3000);
}

function generatePassword(length = 16) {
    const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';
    let password = '';
    
    for (let i = 0; i < length; i++) {
        password += charset.charAt(Math.floor(Math.random() * charset.length));
    }
    
    return password;
}

function copyToClipboard(text) {
    if (navigator.clipboard) {
        navigator.clipboard.writeText(text).then(() => {
            showNotification('Скопировано в буфер обмена');
        }).catch(() => {
            fallbackCopyToClipboard(text);
        });
    } else {
        fallbackCopyToClipboard(text);
    }
}

function fallbackCopyToClipboard(text) {
    const textArea = document.createElement('textarea');
    textArea.value = text;
    textArea.style.position = 'fixed';
    textArea.style.left = '-999999px';
    textArea.style.top = '-999999px';
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();
    
    try {
        document.execCommand('copy');
        showNotification('Скопировано в буфер обмена');
    } catch (err) {
        showNotification('Ошибка при копировании', 'error');
    }
    
    document.body.removeChild(textArea);
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

function throttle(func, limit) {
    let inThrottle;
    return function() {
        const args = arguments;
        const context = this;
        if (!inThrottle) {
            func.apply(context, args);
            inThrottle = true;
            setTimeout(() => inThrottle = false, limit);
        }
    };
}

const searchPasswords = debounce(function(query) {
    const passwordCards = document.querySelectorAll('.password-card');
    const queryLower = query.toLowerCase();
    
    passwordCards.forEach(card => {
        const title = card.querySelector('h3').textContent.toLowerCase();
        const username = card.querySelector('.info-item .value').textContent.toLowerCase();
        
        // Поиск по URL
        const urlElement = card.querySelector('.info-item a.value');
        const url = urlElement ? urlElement.textContent.toLowerCase() : '';
        
        // Поиск по заметкам
        const notesElements = card.querySelectorAll('.info-item .value');
        let notes = '';
        notesElements.forEach((element, index) => {
            if (index > 0) { // Пропускаем первый элемент (username)
                notes += element.textContent.toLowerCase() + ' ';
            }
        });
        
        if (title.includes(queryLower) || 
            username.includes(queryLower) || 
            url.includes(queryLower) || 
            notes.includes(queryLower)) {
            card.style.display = 'block';
        } else {
            card.style.display = 'none';
        }
    });
}, 300);

const searchFiles = debounce(function(query) {
    const fileCards = document.querySelectorAll('.file-card');
    const queryLower = query.toLowerCase();
    
    fileCards.forEach(card => {
        const filename = card.querySelector('h3').textContent.toLowerCase();
        
        if (filename.includes(queryLower)) {
            card.style.display = 'block';
        } else {
            card.style.display = 'none';
        }
    });
}, 300);



function addPasswordGenerator() {
    const passwordInputs = document.querySelectorAll('input[type="password"]');
    
    passwordInputs.forEach(input => {
        if (input.name === 'password') {
            const generateBtn = document.createElement('button');
            generateBtn.type = 'button';
            generateBtn.innerHTML = '<i class="fas fa-dice"></i>';
            generateBtn.className = 'generate-password-btn';
            generateBtn.style.cssText = `
                position: absolute;
                right: 0.5rem;
                top: 50%;
                transform: translateY(-50%);
                background: var(--primary-color);
                border: none;
                border-radius: 0.25rem;
                color: white;
                padding: 0.5rem;
                cursor: pointer;
                transition: all 0.3s ease;
            `;
            
            generateBtn.addEventListener('click', () => {
                input.value = generatePassword();
                input.type = 'text';
                setTimeout(() => {
                    input.type = 'password';
                }, 2000);
            });
            
            const inputContainer = input.parentElement;
            inputContainer.style.position = 'relative';
            inputContainer.appendChild(generateBtn);
        }
    });
}

document.addEventListener('DOMContentLoaded', function() {
    addPasswordGenerator();
});
