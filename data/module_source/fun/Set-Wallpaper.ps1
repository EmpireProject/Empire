# adapted from https://social.technet.microsoft.com/forums/scriptcenter/en-US/9af1769e-197f-4ef3-933f-83cb8f065afb/background-change

Function Set-WallPaper
{
    [CmdletBinding()] Param($WallpaperData)

    $SavePath = "$Env:UserProfile\\AppData\\Local\\wallpaper" + ".jpg"

    Set-Content -value $([System.Convert]::FromBase64String($WallpaperData)) -encoding byte -path $SavePath

add-type @"
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32;
namespace Wallpaper
{
  public enum Style : int
  {
    Tiled, Centered, Stretched, Fit
  }


  public class Setter {
   public const int SetDesktopWallpaper = 20;
   public const int UpdateIniFile = 0x01;
   public const int SendWinIniChange = 0x02;

   [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
   private static extern int SystemParametersInfo (int uAction, int uParam, string lpvParam, int fuWinIni);
   
   public static void SetWallpaper ( string path, Wallpaper.Style style ) {
     SystemParametersInfo( SetDesktopWallpaper, 0, path, UpdateIniFile | SendWinIniChange );
     
     RegistryKey key = Registry.CurrentUser.OpenSubKey("Control Panel\\\\Desktop", true);
     switch( style )
     {
       case Style.Stretched :
         key.SetValue(@"WallpaperStyle", "2") ; 
         key.SetValue(@"TileWallpaper", "0") ;
         break;
       case Style.Centered :
         key.SetValue(@"WallpaperStyle", "1") ; 
         key.SetValue(@"TileWallpaper", "0") ; 
         break;
       case Style.Tiled :
         key.SetValue(@"WallpaperStyle", "1") ; 
         key.SetValue(@"TileWallpaper", "1") ;
         break;
       case Style.Fit :
         key.SetValue(@"WallpaperStyle", "6") ; 
         key.SetValue(@"TileWallpaper", "0") ;
         break;
     }
     key.Close();
   }
  }
}
"@ 

    $null = [Wallpaper.Setter]::SetWallpaper( (Convert-Path $SavePath), "Fit" )
} 