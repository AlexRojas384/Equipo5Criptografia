# Analyze Repository

Analiza el repositorio completo del proyecto y genera un reporte detallado.

## Instrucciones

Explora el repo completo y lanza subagentes en paralelo para analizar:

### Agente 1: Arquitectura
- Estructura de carpetas y organización del código
- Separación de responsabilidades
- Patrones de diseño usados

### Agente 2: Calidad de código
- Código duplicado o redundante
- Funciones muy largas o complejas
- Variables y funciones sin usar

### Agente 3: Seguridad
- Credenciales o secrets hardcodeados
- Dependencias con vulnerabilidades conocidas
- Inputs sin validar

### Agente 4: Deuda técnica
- TODOs y FIXMEs pendientes
- Dependencias desactualizadas
- Código comentado que debería eliminarse

## Output
Genera un reporte consolidado ordenado por severidad con recomendaciones concretas.
Da un resumen ejecutivo al final con las 3 cosas más urgentes a atender.