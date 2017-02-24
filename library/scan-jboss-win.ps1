#!powershell
#
# WANT_JSON
# POWERSHELL_COMMON
#
#Get-WmiObject win32_process -Filter "name like '%java%'" | select commandLine | select-string -pattern "jboss-modules.jar"
$version="garbage"
$found_versions=""
$jarDir = Get-ChildItem C:\ -Filter "jar.exe" -recurse -ErrorAction SilentlyContinue  | Select -expand FullName
$jbossModulesJars = Get-ChildItem C:\ -Filter "jboss-modules.jar" -recurse -ErrorAction SilentlyContinue | select -expand FullName
cd $env:Temp
if ($jbossModulesJars) {
  Foreach ($jboss_module in $jbossModulesJars)
  {
    &"$jarDir" xf "$jboss_module" META-INF/maven/org.jboss.modules/jboss-modules/pom.properties
    $version = Get-Content $env:Temp"\META-INF\maven\org.jboss.modules\jboss-modules\pom.properties" | select-string -pattern "version=(.+)"
    $found = $version -match '=(.+)'
    if ($found) {
        $version_split = $matches[1]
    }
    $found_versions += "$version_split" + "; "
    $jar_dir = "$env:Temp"+"\META-INF"
    Remove-Item $jar_dir -Recurse
  }
}

$jbossRunJars = Get-ChildItem C:\ -Filter "run.jar" -recurse -ErrorAction SilentlyContinue | select -expand FullName
cd $env:Temp
if ($jbossRunJars) {
  Foreach ($jboss_module in $jbossRunJars)
  {
    write-host $jboss_module
    &"$jarDir" xf "$jboss_module" META-INF/maven/org.jboss.modules/jboss-modules/pom.properties
    $version = Get-Content $env:Temp"\META-INF\maven\org.jboss.modules\jboss-modules\pom.properties" | select-string -pattern "version=(.+)"
    $found = $version -match '=(.+)'
    if ($found) {
        $version_split = $matches[1]
    }
    $found_versions += "$version_split" + "; "
    $jar_dir = "$env:Temp"+"\META-INF"
    Remove-Item $jar_dir -Recurse
  }
}

$cores = Get-WmiObject -class win32_processor -Property numberofCores | Select-Object -Property numberOfCores

$result = New-Object psobject @{
    changed = $false
    installed_versions= $found_versions.Substring(0,$found_versions.Length-2)
    hostname= $env:computername
    cores= $cores
};

#echo $result | ConvertTo-Json -Depth 99
Exit-Json $result

