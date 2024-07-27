import React, { useState, useEffect } from "react";
import axios from "axios";
import { toast } from "sonner";

export function Startups() {
  const [startups, setStartups] = useState([]);

  useEffect(() => {
    async function fetchData() {
      try {
        const promise = axios.get("http://localhost:3000/startups");
        toast.promise(promise, {
          loading: 'Loading...',
          success: 'Data fetched successfully!',
          error: 'Error fetching data',
        });
        const response = await promise;
        setStartups(response.data);
        console.log(response.data)
      } catch (error) {
        console.error('Failed to fetch data:', error);
      }
    }
    if(startups.length === 0) {
      fetchData();
    }
  }, []);

  return (
    <div className="mt-8 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 p-8">
      {startups.map((startup, index) => (
        <div key={index} className="border p-4 rounded-lg shadow-md hover:shadow-xl transition-shadow duration-300 ease-in-out">
          {startup.image && (
            <img
              src={startup.image}
              alt={`Logo of ${startup.name}`}
              className="w-32 h-32 rounded-full mx-auto border border-black"
            />
          )}
          <h3 className="text-center text-2xl font-bold mt-4">{startup.name}</h3>
          {Array.isArray(startup.founders) ? (
            <p className="text-center">
              Founders: {startup.founders.map((founder, i) => (
                <span key={founder.id}>
                  {founder.value}{i < startup.founders.length - 1 ? ', ' : ''}
                </span>
              ))}
            </p>
          ) : (
            <p className="text-center">Founders: unknown</p>
          )}

          {Array.isArray(startup.investors) && startup.investors.length > 0? (
            <p className="text-center">
              Investors: {startup.investors.map((investor, i) => (
                <span key={investor[0].investor.id}>
                  {investor[0].investor.value}{i < startup.investors.length - 1 ? ', ' : ''}
                </span>
              ))}
            </p>
          ) : (
          <p className="text-center">Investors: unknown</p>)}
          {/* <p className="text-center">Investors: unknown</p>  } */}
          <p className="text-center">Founded: {(new Date(startup.founded_date)).toDateString()}</p>
          <p className="text-center">Employees: {startup.num_employees}</p>
          <p className="text-center mt-2">{startup.about}</p>
          <div className="text-center mt-4">
          <div className="text-center mt-4">
          <div className="flex justify-center space-x-4 mt-2">
          <a href={startup.website} className="text-blue-600 hover:text-blue-900">Website</a>
            {startup.social_media_links.map((link, i) => {
              if (link) {
                let domain = link.split('//')[1].split('/')[0].replace('www.', '');
                domain = domain.split('.')[0];
                domain = domain.charAt(0).toUpperCase() + domain.slice(1);
                return (
                  <>
                  <span className="text-blue-600">|</span>
                  <a key={i} href={link} className="text-blue-500 hover:text-blue-900">
                    {domain}
                  </a>
                  </>
                );
              }
              return null;
            })}
          </div>
        </div>
        </div>
        </div>
      ))}
    </div>
  );
}
