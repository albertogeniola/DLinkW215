# DLinkW215
This is a C# port of the nice [pyW215](https://github.com/LinuxChristian/pyW215) 
python library for the DLink W215 smart plug. Credits go to both @LinuxChristian and 
to @bikerp, who both contributed to the creation of respectively Python and Javascript
implementations.

## Usage
The library is pretty easy to use:
    
    ```cs
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
    
