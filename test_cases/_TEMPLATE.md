<!--
PLANTILLA ESTÁNDAR DE CASO DE PRUEBA — Casa Monarca
Todos los TC-XX-YY.md deben seguir esta estructura.
Objetivo: pasos FIJOS (sin improvisar) + evidencia CLARA por paso (una PNG por paso).
Reemplaza los <marcadores> y borra este comentario al instanciar.
-->

# Caso de Prueba: TC-XX-YY — <título corto>

| Campo | Valor |
|---|---|
| **Rol(es)** | <Administrador / Coordinador / Operativo / Usuario> |
| **Categoría** | <01 Autenticación / 02 Gestión de Usuarios> |
| **Metodología** | <ruta funcional, p. ej. Login — Dashboard> |
| **Fecha de ejecución** | <YYYY-MM-DD> |
| **Motor** | Playwright MCP (Claude Code) |
| **Estado** | ⬜ PENDIENTE / ✅ PASS / ❌ FAIL |

## Descripción
<Qué valida el caso, 1–2 líneas.>

## Precondiciones
- <Usuario/rol y credenciales usadas.>
- <Estado de la app: servidor en http://127.0.0.1:8000, sesión limpia, firma cargada, etc.>

## Pasos ejecutados
| # | Acción | Ubicación / Selector / Dato | Resultado esperado | Evidencia |
|---|---|---|---|---|
| 1 | <navegar / escribir / clic> | `<URL>` · `<#selector>` · `<dato>` | <qué debe pasar> | `TC-XX-YY_paso-1.png` |
| 2 | … | … | … | `TC-XX-YY_paso-2.png` |

## Resultado esperado
<Comportamiento global esperado, incluyendo el **mensaje o redirect literal** de la app.>

## Resultado obtenido
<Lo que efectivamente ocurrió durante la ejecución.>

## Verificación en BD (si aplica)
<Consulta ORM ejecutada (manage.py shell) y el registro observado. Omitir si no aplica.>

## Evidencia
<Galería: una imagen por paso, en orden.>

![Paso 1](TC-XX-YY_paso-1.png)
![Paso 2](TC-XX-YY_paso-2.png)

## Conclusión
<✅/❌ + frase de cierre: el sistema se comportó como se esperaba / discrepancia detectada.>
