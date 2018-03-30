@echo off
setlocal

set _projectName=OAuth.net
set _solution=src\%_projectName%.sln
set _codeProject=src\%_projectName%\%_projectName%.csproj
set _testProject=src\%_projectName%.tests\%_projectName%.tests.csproj

set _config=%1
if not defined _config (
  set _config=Debug
)

echo Building Config '%_config%'
echo Solution: '%_solution%'
echo Code: '%_codeProject%'
echo Test: '%_testProject%'

echo Restoring packages
dotnet restore %_solution%

echo Cleaning solution
dotnet clean %_solution%

echo Building solution
dotnet build %_solution% -c %_config%

echo Testing solution
dotnet test --no-build -c %_config% %_testProject%

echo Creating NuGet package
dotnet pack --no-build -c %_config% %_codeProject% -o %~dp0\bin\%_config%\package

endlocal
@echo on