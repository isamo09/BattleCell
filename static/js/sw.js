const CACHE_NAME = 'battlecell-v1.0.0';
const urlsToCache = [
    '/',
    '/static/css/style.css',
    '/static/css/fonts.css',
    '/static/css/fontawesome.min.css',
    '/static/js/main.js',
    '/static/fonts/Inter-Regular.woff2',
    '/static/fonts/Inter-Medium.woff2',
    '/static/fonts/Inter-SemiBold.woff2',
    '/static/fonts/Inter-Bold.woff2',
    '/static/icons/icon-192x192.png',
    '/static/icons/icon-512x512.png',
    '/manifest.json'
];

// Установка Service Worker
self.addEventListener('install', function(event) {
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then(function(cache) {
                console.log('Opened cache');
                return cache.addAll(urlsToCache);
            })
    );
});

// Активация Service Worker
self.addEventListener('activate', function(event) {
    event.waitUntil(
        caches.keys().then(function(cacheNames) {
            return Promise.all(
                cacheNames.map(function(cacheName) {
                    if (cacheName !== CACHE_NAME) {
                        console.log('Deleting old cache:', cacheName);
                        return caches.delete(cacheName);
                    }
                })
            );
        })
    );
});

// Перехват запросов
self.addEventListener('fetch', function(event) {
    event.respondWith(
        caches.match(event.request)
            .then(function(response) {
                // Возвращаем кэшированный ответ, если он есть
                if (response) {
                    return response;
                }
                
                // Иначе делаем запрос к сети
                return fetch(event.request).then(
                    function(response) {
                        // Проверяем, что ответ валидный
                        if(!response || response.status !== 200 || response.type !== 'basic') {
                            return response;
                        }
                        
                        // Клонируем ответ
                        var responseToCache = response.clone();
                        
                        caches.open(CACHE_NAME)
                            .then(function(cache) {
                                cache.put(event.request, responseToCache);
                            });
                        
                        return response;
                    }
                );
            })
            .catch(function() {
                // Если нет сети и нет кэша, показываем offline страницу
                if (event.request.destination === 'document') {
                    return caches.match('/offline.html');
                }
            })
    );
});

// Обработка push-уведомлений
self.addEventListener('push', function(event) {
    if (event.data) {
        const data = event.data.json();
        const options = {
            body: data.body,
            icon: '/static/icons/icon-192x192.png',
            badge: '/static/icons/icon-72x72.png',
            vibrate: [100, 50, 100],
            data: {
                dateOfArrival: Date.now(),
                primaryKey: 1
            },
            actions: [
                {
                    action: 'explore',
                    title: 'Открыть',
                    icon: '/static/icons/icon-72x72.png'
                },
                {
                    action: 'close',
                    title: 'Закрыть',
                    icon: '/static/icons/icon-72x72.png'
                }
            ]
        };
        
        event.waitUntil(
            self.registration.showNotification(data.title, options)
        );
    }
});

// Обработка кликов по уведомлениям
self.addEventListener('notificationclick', function(event) {
    event.notification.close();
    
    if (event.action === 'explore') {
        event.waitUntil(
            clients.openWindow('/')
        );
    }
});
