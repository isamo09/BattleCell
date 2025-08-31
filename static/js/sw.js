const CACHE_NAME = "battlecell-v1.0.0"
const urlsToCache = [
  "/",
  "/static/css/style.css",
  "/static/css/fonts.css",
  "/static/css/fontawesome.min.css",
  "/static/js/main.js",
  "/static/fonts/Inter-Regular.woff2",
  "/static/fonts/Inter-Medium.woff2",
  "/static/fonts/Inter-SemiBold.woff2",
  "/static/fonts/Inter-Bold.woff2",
  "/static/icons/icon-192x192.png",
  "/static/icons/icon-512x512.png",
  "/manifest.json",
  "/sw.js",
  "/offline",
]

// Установка Service Worker
self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      console.log("Opened cache")
      return cache.addAll(urlsToCache)
    }),
  )
})

// Активация Service Worker
self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((cacheNames) =>
      Promise.all(
        cacheNames.map((cacheName) => {
          if (cacheName !== CACHE_NAME) {
            console.log("Deleting old cache:", cacheName)
            return caches.delete(cacheName)
          }
        }),
      ),
    ),
  )
})

// Перехват запросов
self.addEventListener("fetch", (event) => {
  if (
    event.request.url.includes("/login") ||
    event.request.url.includes("/logout") ||
    event.request.url.includes("/register") ||
    event.request.method !== "GET"
  ) {
    return fetch(event.request)
  }

  event.respondWith(
    caches
      .match(event.request)
      .then((response) => {
        // Возвращаем кэшированный ответ, если он есть
        if (response) {
          return response
        }

        // Иначе делаем запрос к сети
        return fetch(event.request).then((response) => {
          // Проверяем, что ответ валидный
          if (!response || response.status !== 200 || response.type !== "basic") {
            return response
          }

          // Клонируем ответ
          var responseToCache = response.clone()

          caches.open(CACHE_NAME).then((cache) => {
            cache.put(event.request, responseToCache)
          })

          return response
        })
      })
      .catch(() => {
        // Если нет сети и нет кэша, показываем offline страницу
        if (event.request.destination === "document") {
          return caches.match("/offline").then((response) => {
            if (response) {
              return response
            }
            // Fallback offline page if cached version not available
            return new Response(
              `
                            <!DOCTYPE html>
                            <html lang="ru">
                            <head>
                                <meta charset="UTF-8">
                                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                                <title>BattleCell - Офлайн</title>
                                <style>
                                    body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
                                    .offline-message { max-width: 400px; margin: 0 auto; }
                                    .btn { background: #6366f1; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; }
                                </style>
                            </head>
                            <body>
                                <div class="offline-message">
                                    <h1>Нет подключения к интернету</h1>
                                    <p>BattleCell работает в автономном режиме.</p>
                                    <button class="btn" onclick="window.location.reload()">Попробовать снова</button>
                                </div>
                            </body>
                            </html>
                        `,
              {
                headers: { "Content-Type": "text/html" },
              },
            )
          })
        }
      }),
  )
})

// Обработка push-уведомлений
self.addEventListener("push", (event) => {
  if (event.data) {
    const data = event.data.json()
    const options = {
      body: data.body,
      icon: "/static/icons/icon-192x192.png",
      badge: "/static/icons/icon-72x72.png",
      vibrate: [100, 50, 100],
      data: {
        dateOfArrival: Date.now(),
        primaryKey: 1,
      },
      actions: [
        {
          action: "explore",
          title: "Открыть",
          icon: "/static/icons/icon-72x72.png",
        },
        {
          action: "close",
          title: "Закрыть",
          icon: "/static/icons/icon-72x72.png",
        },
      ],
    }

    event.waitUntil(self.registration.showNotification(data.title, options))
  }
})

// Обработка кликов по уведомлениям
self.addEventListener("notificationclick", (event) => {
  event.notification.close()

  if (event.action === "explore") {
    event.waitUntil(clients.openWindow("/"))
  }
})
