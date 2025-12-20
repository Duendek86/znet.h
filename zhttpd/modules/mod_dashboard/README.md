# Dashboard Module

Panel de control modular y estadísticas en tiempo real para el servidor HTTP zhttpd.

## 🚀 Características

- **Dashboard Modular**: Nueva interfaz con soporte para pestañas y gestión de módulos.
- **Autenticación HTTP Basic Auth**: Acceso seguro con credenciales.
- **Estadísticas en Tiempo Real**: Actualización automática cada 2 segundos.
- **Gestión de Módulos**: Habilitar/deshabilitar módulos del sistema en tiempo real.
- **Múltiples Métricas**:
  - Clientes activos concurrentes
  - Total de requests procesados
  - Tiempo promedio de respuesta
  - Tráfico de red (bytes/MB enviados)
  - Requests por segundo
- **Visualizaciones Interactivas**: 4 gráficas con Chart.js
- **Historial**: Datos de los últimos 60 segundos
- **Diseño Premium**: Tema oscuro moderno y responsivo

## 🔐 Credenciales de Acceso

Por defecto, las credenciales son:
- **Usuario**: `admin`
- **Contraseña**: `stats123`
- **Realm**: `ZHTTPD Dashboard`

## 📡 API Endpoints

El módulo expone los siguientes endpoints (requieren autenticación):

### Estadísticas
- `GET /api/dashboard/current`: Retorna las estadísticas actuales del servidor.
- `GET /api/dashboard/history`: Retorna los datos históricos (últimas 30 muestras).
- `POST /api/dashboard/reset`: Reinicia todos los contadores de estadísticas.

### Gestión de Módulos
- `GET /api/modules/list`: Lista los módulos instalados y su estado.
- `POST /api/modules/toggle`: Habilita o deshabilita un módulo (`{module: "name", enabled: true/false}`).

## 🌐 Acceso al Dashboard

1. Inicia el servidor zhttpd.
2. Navega a: `http://localhost:8080/dashboard/dashboard.html` (o simplemente `/dashboard` si está configurado).
3. Ingresa las credenciales.
4. Serás redirigido al dashboard.

## 🔧 Arquitectura Técnica

### Backend (C Module)
- **Archivo**: `modules/mod_dashboard.c`
- **Gestión de Assets**: Sirve archivos estáticos directamente desde `modules/mod_dashboard/`.
- **Rastreo thread-safe**: Contadores atómicos para concurrencia.
- **Configuración Dinámica**: Lectura y escritura atómica de `modules.conf`.

### Frontend
- **Ubicación**: Archivos servidos desde el directorio del módulo.
- **HTML/CSS**: Diseño moderno con animaciones CSS.
- **JavaScript**: Vanilla JS con fetch API.
- **Agnóstico**: No requiere dependencias externas más allá de Chart.js (CDN).

## 📝 Personalización

### Cambiar Credenciales

Edita `modules/mod_dashboard.c`:
```c
#define AUTH_HEADER "Authorization: Basic <tu_base64>"
```

### Configuración

El archivo `modules.conf` se actualiza automáticamente al usar la interfaz de gestión, pero puede editarse manualmente:
```
load modules/mod_dashboard.dll
```

## 🐛 Troubleshooting

**El módulo no carga**:
- Verifica que `modules.conf` incluye `load modules/mod_dashboard.dll`
- Asegúrate de haber eliminado referencias antiguas a `mod_stats.dll`.

**Error 401 en el dashboard**:
- Verifica las credenciales.
- Limpia sessionStorage del navegador (`dashboardAuth`).

**Las gráficas no se actualizan**:
- Verifica la consola del navegador para errores.
- Asegúrate de que el servidor está corriendo.
