package org.syncmob.mobile.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

val Green = Color(0xFF5AC878)
val Amber = Color(0xFFE6AA3C)
val Red = Color(0xFFE15F5F)
val Dim = Color(0xFF9096A0)

private val DarkColors = darkColorScheme(
    primary = Green,
    onPrimary = Color(0xFF07130B),
    secondary = Color(0xFF7FB6FF),
    background = Color(0xFF101418),
    surface = Color(0xFF161B21),
    error = Red,
)

private val LightColors = lightColorScheme(
    primary = Color(0xFF177A3B),
    secondary = Color(0xFF1B5FA8),
    error = Color(0xFFB3261E),
)

@Composable
fun SyncMobTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = if (isSystemInDarkTheme()) DarkColors else LightColors,
        content = content,
    )
}
