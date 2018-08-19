# DLinkW215
This is a C# port of the nice [pyW215](https://github.com/LinuxChristian/pyW215) 
python library for the DLink W215 smart plug. Credits go to both @LinuxChristian and 
to @bikerp, who both contributed to the creation of respectively Python and Javascript
implementations.

## Installation
In order to use this library in your projects, you might either reference the package via NuGet or download the project and reference the library externally. 

I strongly suggest to use NuGet package manager to do so. The package has been pushed on NuGet repository: https://www.nuget.org/packages/DLinkW215/.

From the package manager console:

    PM> Install-Package DLinkW215 -Version 0.0.1

From .NET CLI

    > dotnet add package DLinkW215 --version 0.0.1

From Packet CLI

    > paket add DLinkW215 --version 0.0.1

## Usage
The library is pretty easy to use:
    
    ```cs
    // The first parameter is the IP address of the power plug
    // while the second one is the ACCESS CODE printed on the plug itself
    var plug = new DLinkW215SmartPlug("192.168.1.9", "123456");
    
    // Returns the current power switch state    
    var state = plug.GetState(); 

    // Return the current power consumption in Watts. If an error occurred, null is returned.
    var powerConsumption = plug.GetCurrentConsumption();
    if (powerConsumption==null)
        Console.Out.WriteLine("Current consumption is " + powerConsumption + " Watts");
    else
        Console.Out.WriteLine("An error occurred and it was not possible to read the power consumtpion from the device");
    
    // Same thing happens for the following:
    // plug.GetTotalConsumption()
    // plug.GetTemperature() // In Celsius!
    
    // Turn the switch On
    plug.SetState(DLinkW215.DLinkW215SmartPlug.On);

    // Turn the switch Off
    plug.SetState(DLinkW215.DLinkW215SmartPlug.Off);
    ```
    

## Notes and known issues
The library works. However no verbose error handling system has been implemented. This means that, if there is something wrong, exception are not well handled. Most of the APIs will simply catch any exception and return null instead. 