import React, { useState, useEffect } from "react";
import axios from "axios";
import { toast } from "sonner";

export function Dashboard() {
  const [profiles, setProfiles] = useState([]);
  const [filteredProfiles, setFilteredProfiles] = useState([]);
  const [filterOn, setFilterOn] = useState(false);
  const [data, setData] = useState({});

  // Fetch data on component mount
  useEffect(() => {
    const fetchData = async () => {
      try {
        const promise = axios.get("http://localhost:3000/data");
        toast.promise(promise, {
          loading: 'Loading...',
          success: 'Data fetched successfully!',
          error: 'Error fetching data',
        });
    
        const response = await promise; 
        setData(response.data);
      } catch (error) {
        console.error('Failed to fetch data:', error);
      }
    };
    
    fetchData();
  }, []);

  // Update profiles when data changes
  useEffect(() => {
    if (data.founders && data.investors) {
      const combinedProfiles = [...data.founders, ...data.investors].sort(
        () => 0.5 - Math.random()
      );
      setProfiles(combinedProfiles);
    }
  }, [data]); 

  const showFounders = () => {
    setFilterOn(true);
    setFilteredProfiles([]);
    setFilteredProfiles(data.founders);
  };

  const showInvestors = () => {
    setFilterOn(true);
    setFilteredProfiles([]);
    setFilteredProfiles(data.investors);
  };
  const removeFilter = () => {
    setFilterOn(false);
    setFilteredProfiles([]);
  }
  function handleSelectChange(event) {
    const selectedValue = event.target.value;
    console.log("Selected value:", selectedValue);
  
    if (selectedValue === "founders") {
      showFounders();
    } else if (selectedValue === "investors") {
      showInvestors();
    }
  }
  const profilesToShow = filterOn ? filteredProfiles : profiles;

  return (
    <>
      <div className="flex justify-center mt-4 pt-16 gap-4">
      <h1 className="self-center text-xl">Filter : </h1>
      <select onChange={handleSelectChange} className="border border-black rounded-lg">
        <option value="founders">Founders</option>
        <option value="investors">Investors</option>
      </select>
      <button
        className=" border-2 px-3 py-1 rounded-lg bg-red-500 hover:bg-red-400 text-white font-semibold"
        onClick={removeFilter}
      >
        Remove
      </button>
    </div>
      <div className="mt-8 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 p-8">
        {profilesToShow.map((profile) => (
          <div key={profile._id} className="border p-4 rounded-lg shadow-md hover:scale-110 hover:z-10 transition-transform duration-200 hover:bg-white">
            <img
              src={profile.profile_picture}
              alt={`${profile.name}'s profile`}
              className="w-16 h-16 rounded-full mx-auto"
            />
            <h2 className="text-center text-xl font-semibold mt-2">
              {profile.name}
            </h2>
            <p className="text-center text-gray-600">{profile.title}</p>
            {profile.company && (
              <p className="text-center text-gray-600">{profile.company}</p>
            )}
            {profile.firm && (
              <p className="text-center text-gray-600">{profile.firm}</p>
            )}
            <p className="text-center text-gray-600">{profile.location}</p>
            <div className="flex justify-center space-x-4 mt-4">
              <a href={profile.linkedin} className="text-blue-500  hover:text-blue-900">
                LinkedIn
              </a>
              <a href={profile.twitter} className="text-blue-500  hover:text-blue-900">
                Twitter
              </a>
            </div>
          </div>
        ))}
      </div>
    </>
  );
}
